package synth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"modernc.org/sqlite"
)

// osquery registers extra SQL functions on its SQLite connection
// (osquery/sql/sqlite_string.cpp, sqlite_encoding.cpp and sqlite_math.cpp).
// Servers use them in ordinary queries, for example
// CAST(split(version, '.', 0) AS INTEGER) to compare major versions, so the
// SQLite evaluator registers the same functions with the same semantics.
//
// Every function is deterministic, does no I/O and returns at most
// maxFuncResult bytes, the connection's SQLITE_LIMIT_LENGTH. Regular
// expressions use Go's RE2 engine, which runs in linear time; patterns are
// limited to regexMaxSize bytes, as osquery's --regex_max_size default.
// RE2 has no backreferences or lookaround, so a pattern that uses them is an
// "Invalid regex" error, where osquery's ECMAScript engine would accept it.

const (
	// maxFuncResult bounds a function's result (the SQLITE_LIMIT_LENGTH
	// set on every connection).
	maxFuncResult = 4 << 20
	// regexMaxSize is osquery's default --regex_max_size.
	regexMaxSize = 256
)

var errFuncTooBig = errors.New("string or blob too big")

// osqueryError is an error message exactly as osquery words it (osquery
// capitalises them, unlike Go error strings).
type osqueryError string

func (e osqueryError) Error() string { return string(e) }

const errInvalidRegex = osqueryError("Invalid regex")

type sqlFunc struct {
	name  string
	nArgs int32
	fn    func(args []driver.Value) (driver.Value, error)
}

// osqueryFuncs are registered whether or not SQLite has a function of
// the same name: SQLite's own concat_ws skips the separator after a NULL
// argument, osquery's does not.
var osqueryFuncs = []sqlFunc{
	{"split", 3, func(a []driver.Value) (driver.Value, error) { return splitFunc(a, tokenSplit) }},
	{"regex_split", 3, func(a []driver.Value) (driver.Value, error) { return splitFunc(a, regexSplit) }},
	{"regex_match", 3, regexMatchFunc},
	{"concat", -1, func(a []driver.Value) (driver.Value, error) { return concatFunc("", a) }},
	{"concat_ws", -1, concatWSFunc},
	{"inet_aton", 1, inetAtonFunc},
	{"to_base64", 1, func(a []driver.Value) (driver.Value, error) { return base64Func(a, b64Encode) }},
	{"from_base64", 1, func(a []driver.Value) (driver.Value, error) { return base64Func(a, b64Decode) }},
	{"conditional_to_base64", 1, func(a []driver.Value) (driver.Value, error) { return base64Func(a, b64EncodeConditional) }},
	// SQLite's one-argument log() is the base-10 logarithm; osquery's is
	// the natural logarithm.
	{"log", 1, mathFunc1(math.Log)},
}

// osqueryMathFuncs are registered only when this SQLite build lacks them
// (it is built with SQLITE_ENABLE_MATH_FUNCTIONS, which has all of these but
// cot). The built-in ceil and floor return a REAL where osquery returns an
// INTEGER, but both read the same as text, which is how results are sent.
var osqueryMathFuncs = []sqlFunc{
	{"sqrt", 1, mathFunc1(math.Sqrt)},
	{"acos", 1, mathFunc1(math.Acos)},
	{"asin", 1, mathFunc1(math.Asin)},
	{"atan", 1, mathFunc1(math.Atan)},
	{"cos", 1, mathFunc1(math.Cos)},
	{"sin", 1, mathFunc1(math.Sin)},
	{"tan", 1, mathFunc1(math.Tan)},
	{"cot", 1, func(a []driver.Value) (driver.Value, error) { // 1/tan(x) sets no errno
		if a[0] == nil {
			return nil, nil
		}
		return 1 / math.Tan(floatArg(a[0])), nil
	}},
	{"exp", 1, mathFunc1(math.Exp)},
	{"log10", 1, mathFunc1(math.Log10)},
	{"power", 2, powerFunc},
	{"ceil", 1, roundingFunc(math.Ceil)},
	{"floor", 1, roundingFunc(math.Floor)},
	{"degrees", 1, mathFunc1(func(x float64) float64 { return 180 * x / math.Pi })},
	{"radians", 1, mathFunc1(func(x float64) float64 { return x * math.Pi / 180 })},
	{"pi", 0, func([]driver.Value) (driver.Value, error) { return math.Pi, nil }},
}

var (
	registerFuncsOnce sync.Once
	errRegisterFuncs  error
)

// registerOSQueryFunctions registers the functions above with the SQLite
// driver, once, before the evaluator opens its first connection.
func registerOSQueryFunctions(ctx context.Context) error {
	registerFuncsOnce.Do(func() {
		missing, err := missingFunctions(ctx, osqueryMathFuncs)
		if err != nil {
			errRegisterFuncs = err
			return
		}
		for _, f := range append(append([]sqlFunc(nil), osqueryFuncs...), missing...) {
			fn := f.fn
			err := sqlite.RegisterDeterministicScalarFunction(f.name, f.nArgs, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
				v, err := fn(args)
				if s, ok := v.(string); ok && len(s) > maxFuncResult {
					return nil, errFuncTooBig
				}
				return v, err
			})
			if err != nil {
				errRegisterFuncs = fmt.Errorf("register %s: %w", f.name, err)
				return
			}
		}
	})
	return errRegisterFuncs
}

// missingFunctions returns the functions this SQLite build doesn't have.
func missingFunctions(ctx context.Context, funcs []sqlFunc) ([]sqlFunc, error) {
	db, err := sql.Open("sqlite", sqliteDSN)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var missing []sqlFunc
	for _, f := range funcs {
		args := strings.TrimSuffix(strings.Repeat("1, ", int(f.nArgs)), ", ")
		var v interface{}
		// #nosec G202 -- the function names and arguments are constants above.
		err := db.QueryRowContext(ctx, "SELECT "+f.name+"("+args+")").Scan(&v)
		if err != nil && strings.Contains(err.Error(), "no such function") {
			missing = append(missing, f)
		} else if err != nil {
			return nil, err
		}
	}
	return missing, nil
}

// --- argument conversion, as sqlite3_value_text / _int / _double do ---

// textArg is v as SQLite renders it as text.
func textArg(v driver.Value) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return realText(x)
	case bool:
		if x {
			return "1"
		}
		return "0"
	default:
		return fmt.Sprint(x)
	}
}

// realText formats a REAL the way SQLite does ("%!.15g": 2.0 is "2.0").
func realText(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return ""
	}
	s := strconv.FormatFloat(f, 'g', 15, 64)
	if !strings.ContainsAny(s, ".e") {
		s += ".0"
	}
	return s
}

var reNumericPrefix = regexp.MustCompile(`^\s*[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?`)

// floatArg is v as a REAL: text is read up to its first non-numeric
// character, and is 0 when it has no numeric prefix.
func floatArg(v driver.Value) float64 {
	switch x := v.(type) {
	case int64:
		return float64(x)
	case float64:
		return x
	case bool:
		if x {
			return 1
		}
		return 0
	}
	m := reNumericPrefix.FindString(textArg(v))
	f, _ := strconv.ParseFloat(strings.TrimSpace(m), 64)
	return f
}

// indexArg is v as sqlite3_value_int reads it (a 32-bit integer), or -1
// when that is negative: osquery casts it to size_t, so a negative index
// is out of range.
func indexArg(v driver.Value) int {
	var i int64
	switch x := v.(type) {
	case int64:
		i = x
	default:
		f := floatArg(v)
		if f >= math.MaxInt64 || f <= math.MinInt64 {
			return -1
		}
		i = int64(f)
	}
	i32 := int32(i) // #nosec G115 -- sqlite3_value_int truncates the same way
	if i32 < 0 {
		return -1
	}
	return int(i32)
}

func anyNull(args []driver.Value) bool {
	for _, a := range args {
		if a == nil {
			return true
		}
	}
	return false
}

// --- string functions (sqlite_string.cpp) ---

// tokenSplit is osquery::split: split on any of the token characters, drop
// empty pieces and trim whitespace from each.
func tokenSplit(input, tokens string) ([]string, error) {
	fields := strings.FieldsFunc(input, func(r rune) bool { return strings.ContainsRune(tokens, r) })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.Trim(f, " \t\n\v\f\r"))
	}
	return out, nil
}

// regexSplit splits on a regular expression, keeping empty pieces except a
// trailing one, as std::sregex_token_iterator with -1 does.
func regexSplit(input, pattern string) ([]string, error) {
	if len(pattern) > regexMaxSize {
		return nil, errInvalidRegex
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errInvalidRegex
	}
	var out []string
	prev := 0
	for _, loc := range re.FindAllStringIndex(input, -1) {
		out = append(out, input[prev:loc[0]])
		prev = loc[1]
	}
	if prev < len(input) {
		out = append(out, input[prev:])
	}
	return out, nil
}

// splitFunc is split(str, tokens, index) and regex_split(str, regex, index):
// the index-th piece, or NULL when there is none.
func splitFunc(args []driver.Value, split func(input, token string) ([]string, error)) (driver.Value, error) {
	if anyNull(args) {
		return nil, nil
	}
	token := textArg(args[1])
	if token == "" {
		return nil, osqueryError("Invalid input to split function")
	}
	pieces, err := split(textArg(args[0]), token)
	if err != nil {
		return nil, err
	}
	i := indexArg(args[2])
	if i < 0 || i >= len(pieces) {
		return nil, nil
	}
	return pieces[i], nil
}

// regexMatchFunc is regex_match(str, regex, index): the index-th group of
// the first match (0 is the whole match), or NULL when nothing matches.
func regexMatchFunc(args []driver.Value) (driver.Value, error) {
	if anyNull(args) {
		return nil, nil
	}
	pattern := textArg(args[1])
	if len(pattern) > regexMaxSize {
		return nil, osqueryError(fmt.Sprintf("Invalid regex: too big, max size is %d bytes", regexMaxSize))
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, errInvalidRegex
	}
	loc := re.FindStringSubmatchIndex(textArg(args[0]))
	if loc == nil {
		return nil, nil
	}
	i := indexArg(args[2])
	if i < 0 || 2*i+1 >= len(loc) {
		return nil, nil
	}
	if loc[2*i] < 0 {
		return "", nil // a group that took no part in the match
	}
	return textArg(args[0])[loc[2*i]:loc[2*i+1]], nil
}

// concatFunc joins the non-NULL arguments. As in osquery, sep follows every
// non-NULL argument but the last argument, so concat_ws('-', 'a', NULL) is
// "a-". No arguments give NULL.
func concatFunc(sep string, args []driver.Value) (driver.Value, error) {
	if len(args) == 0 {
		return nil, nil
	}
	var b strings.Builder
	for i, a := range args {
		if a == nil {
			continue
		}
		b.WriteString(textArg(a))
		if sep != "" && i+1 < len(args) {
			b.WriteString(sep)
		}
		if b.Len() > maxFuncResult {
			return nil, errFuncTooBig
		}
	}
	return b.String(), nil
}

func concatWSFunc(args []driver.Value) (driver.Value, error) {
	if len(args) == 0 {
		return nil, osqueryError("Missing separator to concat_ws")
	}
	sep := ""
	if args[0] != nil {
		sep = textArg(args[0])
	}
	return concatFunc(sep, args[1:])
}

// inetAtonFunc is inet_aton(ip): a dotted IPv4 address as an integer, NULL
// for anything else (IPv6 included).
func inetAtonFunc(args []driver.Value) (driver.Value, error) {
	if args[0] == nil {
		return nil, nil
	}
	s := textArg(args[0])
	if strings.Contains(s, ":") {
		return nil, nil
	}
	if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
		b := addr.As4()
		return int64(b[0])<<24 | int64(b[1])<<16 | int64(b[2])<<8 | int64(b[3]), nil
	}
	return nil, nil
}

// --- encoding functions (sqlite_encoding.cpp) ---

type b64Mode int

const (
	b64Encode b64Mode = iota
	b64EncodeConditional
	b64Decode
)

func base64Func(args []driver.Value, mode b64Mode) (driver.Value, error) {
	if args[0] == nil {
		return nil, nil
	}
	in := textArg(args[0])
	switch mode {
	case b64EncodeConditional:
		if isPrintable(in) {
			return in, nil
		}
		return base64.StdEncoding.EncodeToString([]byte(in)), nil
	case b64Encode:
		return base64.StdEncoding.EncodeToString([]byte(in)), nil
	default:
		// osquery drops line breaks and trailing padding, and answers an
		// empty string for input it cannot decode.
		in = strings.ReplaceAll(in, "\n", "")
		in = strings.ReplaceAll(in, "\r", "")
		in = strings.TrimRight(in, "=")
		if out, err := base64.RawStdEncoding.DecodeString(in); err == nil {
			return string(out), nil
		}
		return "", nil
	}
}

// isPrintable is osquery's isPrintable: every byte is printable ASCII.
func isPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x7f || s[i] <= 0x1f {
			return false
		}
	}
	return true
}

// --- math functions (sqlite_math.cpp) ---

// mathError is the C library's error for a result that sets errno.
func mathError(in, out float64) error {
	switch {
	case math.IsNaN(out) && !math.IsNaN(in):
		return osqueryError("Numerical argument out of domain")
	case math.IsInf(out, 0) && !math.IsInf(in, 0):
		return osqueryError("Numerical result out of range")
	}
	return nil
}

func mathFunc1(f func(float64) float64) func([]driver.Value) (driver.Value, error) {
	return func(args []driver.Value) (driver.Value, error) {
		if args[0] == nil {
			return nil, nil
		}
		x := floatArg(args[0])
		v := f(x)
		if err := mathError(x, v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

func powerFunc(args []driver.Value) (driver.Value, error) {
	if anyNull(args) {
		return nil, nil
	}
	x, y := floatArg(args[0]), floatArg(args[1])
	v := math.Pow(x, y)
	if err := mathError(x, v); err != nil {
		return nil, err
	}
	return v, nil
}

// roundingFunc is osquery's ceil/floor: an INTEGER argument is returned as
// is, anything else is rounded and returned as an INTEGER.
func roundingFunc(f func(float64) float64) func([]driver.Value) (driver.Value, error) {
	return func(args []driver.Value) (driver.Value, error) {
		switch x := args[0].(type) {
		case nil:
			return nil, nil
		case int64:
			return x, nil
		default:
			return int64(f(floatArg(x))), nil
		}
	}
}
