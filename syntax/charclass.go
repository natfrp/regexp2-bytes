package syntax

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"unicode"
)

// CharSet combines start-end byte ranges and unicode categories representing a set of characters
type CharSet struct {
	ranges     []singleRange
	categories []category
	sub        *CharSet //optional subtractor
	negate     bool
	anything   bool
}

type category struct {
	negate bool
	cat    string
}

type singleRange struct {
	first byte
	last  byte
}

const (
	spaceCategoryText = " "
	wordCategoryText  = "W"
)

var (
	ecmaSpace = []byte{0x0009, 0x000e, 0x0020, 0x0021, 0x00a0, 0x00a1}
	ecmaWord  = []byte{0x0030, 0x003a, 0x0041, 0x005b, 0x005f, 0x0060, 0x0061, 0x007b}
	ecmaDigit = []byte{0x0030, 0x003a}

	re2Space = []byte{0x0009, 0x000b, 0x000c, 0x000e, 0x0020, 0x0021}
)

var (
	AnyClass          = getCharSetFromOldString([]byte{0}, false)
	ECMAAnyClass      = getCharSetFromOldString([]byte{0, 0x000a, 0x000b, 0x000d, 0x000e}, false)
	NoneClass         = getCharSetFromOldString(nil, false)
	ECMAWordClass     = getCharSetFromOldString(ecmaWord, false)
	NotECMAWordClass  = getCharSetFromOldString(ecmaWord, true)
	ECMASpaceClass    = getCharSetFromOldString(ecmaSpace, false)
	NotECMASpaceClass = getCharSetFromOldString(ecmaSpace, true)
	ECMADigitClass    = getCharSetFromOldString(ecmaDigit, false)
	NotECMADigitClass = getCharSetFromOldString(ecmaDigit, true)

	WordClass     = getCharSetFromCategoryString(false, false, wordCategoryText)
	NotWordClass  = getCharSetFromCategoryString(true, false, wordCategoryText)
	SpaceClass    = getCharSetFromCategoryString(false, false, spaceCategoryText)
	NotSpaceClass = getCharSetFromCategoryString(true, false, spaceCategoryText)
	DigitClass    = getCharSetFromCategoryString(false, false, "Nd")
	NotDigitClass = getCharSetFromCategoryString(false, true, "Nd")

	RE2SpaceClass    = getCharSetFromOldString(re2Space, false)
	NotRE2SpaceClass = getCharSetFromOldString(re2Space, true)
)

var unicodeCategories = func() map[string]*unicode.RangeTable {
	retVal := make(map[string]*unicode.RangeTable)
	for k, v := range unicode.Scripts {
		retVal[k] = v
	}
	for k, v := range unicode.Categories {
		retVal[k] = v
	}
	for k, v := range unicode.Properties {
		retVal[k] = v
	}
	return retVal
}()

func getCharSetFromCategoryString(negateSet bool, negateCat bool, cats ...string) func() *CharSet {
	if negateCat && negateSet {
		panic("BUG!  You should only negate the set OR the category in a constant setup, but not both")
	}

	c := CharSet{negate: negateSet}

	c.categories = make([]category, len(cats))
	for i, cat := range cats {
		c.categories[i] = category{cat: cat, negate: negateCat}
	}
	return func() *CharSet {
		//make a copy each time
		local := c
		//return that address
		return &local
	}
}

func getCharSetFromOldString(setText []byte, negate bool) func() *CharSet {
	c := CharSet{}
	if len(setText) > 0 {
		fillFirst := false
		l := len(setText)
		if negate {
			if setText[0] == 0 {
				setText = setText[1:]
			} else {
				l++
				fillFirst = true
			}
		}

		if l%2 == 0 {
			c.ranges = make([]singleRange, l/2)
		} else {
			c.ranges = make([]singleRange, l/2+1)
		}

		first := true
		if fillFirst {
			c.ranges[0] = singleRange{first: 0}
			first = false
		}

		i := 0
		for _, r := range setText {
			if first {
				// lower bound in a new range
				c.ranges[i] = singleRange{first: r}
				first = false
			} else {
				c.ranges[i].last = r - 1
				i++
				first = true
			}
		}
		if !first {
			c.ranges[i].last = 0xff
		}
	}

	return func() *CharSet {
		local := c
		return &local
	}
}

// Copy makes a deep copy to prevent accidental mutation of a set
func (c CharSet) Copy() CharSet {
	ret := CharSet{
		anything: c.anything,
		negate:   c.negate,
	}

	ret.ranges = append(ret.ranges, c.ranges...)
	ret.categories = append(ret.categories, c.categories...)

	if c.sub != nil {
		sub := c.sub.Copy()
		ret.sub = &sub
	}

	return ret
}

// gets a human-readable description for a set string
func (c CharSet) String() string {
	buf := &bytes.Buffer{}
	buf.WriteByte('[')

	if c.IsNegated() {
		buf.WriteByte('^')
	}

	for _, r := range c.ranges {

		buf.WriteString(CharDescription(r.first))
		if r.first != r.last {
			if r.last-r.first != 1 {
				//groups that are 1 char apart skip the dash
				buf.WriteByte('-')
			}
			buf.WriteString(CharDescription(r.last))
		}
	}

	for _, c := range c.categories {
		buf.WriteString(c.String())
	}

	if c.sub != nil {
		buf.WriteByte('-')
		buf.WriteString(c.sub.String())
	}

	buf.WriteByte(']')

	return buf.String()
}

// mapHashFill converts a charset into a buffer for use in maps
func (c CharSet) mapHashFill(buf *bytes.Buffer) {
	if c.negate {
		buf.WriteByte(0)
	} else {
		buf.WriteByte(1)
	}

	binary.Write(buf, binary.LittleEndian, len(c.ranges))
	binary.Write(buf, binary.LittleEndian, len(c.categories))
	for _, r := range c.ranges {
		buf.WriteByte(r.first)
		buf.WriteByte(r.last)
	}
	for _, ct := range c.categories {
		buf.WriteString(ct.cat)
		if ct.negate {
			buf.WriteByte(1)
		} else {
			buf.WriteByte(0)
		}
	}

	if c.sub != nil {
		c.sub.mapHashFill(buf)
	}
}

// CharIn returns true if the byte is in our character set (either ranges or categories).
// It handles negations and subtracted sub-charsets.
func (c CharSet) CharIn(ch byte) bool {
	val := false
	// in s && !s.subtracted

	//check ranges
	for _, r := range c.ranges {
		if ch < r.first {
			continue
		}
		if ch <= r.last {
			val = true
			break
		}
	}

	//check categories if we haven't already found a range
	if !val && len(c.categories) > 0 {
		for _, ct := range c.categories {
			// special categories...then unicode
			if ct.cat == spaceCategoryText {
				if unicode.IsSpace(rune(ch)) {
					// we found a space so we're done
					// negate means this is a "bad" thing
					val = !ct.negate
					break
				} else if ct.negate {
					val = true
					break
				}
			} else if ct.cat == wordCategoryText {
				if IsWordChar(ch) {
					val = !ct.negate
					break
				} else if ct.negate {
					val = true
					break
				}
			} else if unicode.Is(unicodeCategories[ct.cat], rune(ch)) {
				// if we're in this unicode category then we're done
				// if negate=true on this category then we "failed" our test
				// otherwise we're good that we found it
				val = !ct.negate
				break
			} else if ct.negate {
				val = true
				break
			}
		}
	}

	// negate the whole char set
	if c.negate {
		val = !val
	}

	// get subtracted recurse
	if val && c.sub != nil {
		val = !c.sub.CharIn(ch)
	}

	//log.Printf("Char '%v' in %v == %v", string(ch), c.String(), val)
	return val
}

func (c category) String() string {
	switch c.cat {
	case spaceCategoryText:
		if c.negate {
			return "\\S"
		}
		return "\\s"
	case wordCategoryText:
		if c.negate {
			return "\\W"
		}
		return "\\w"
	}
	if _, ok := unicodeCategories[c.cat]; ok {

		if c.negate {
			return "\\P{" + c.cat + "}"
		}
		return "\\p{" + c.cat + "}"
	}
	return "Unknown category: " + c.cat
}

// CharDescription Produces a human-readable description for a single character.
func CharDescription(ch byte) string {
	/*if ch == '\\' {
		return "\\\\"
	}

	if ch > ' ' && ch <= '~' {
		return string(ch)
	} else if ch == '\n' {
		return "\\n"
	} else if ch == ' ' {
		return "\\ "
	}*/

	b := &bytes.Buffer{}
	escape(b, ch, false) //fmt.Sprintf("%U", ch)
	return b.String()
}

// According to UTS#18 Unicode Regular Expressions (http://www.unicode.org/reports/tr18/)
// RL 1.4 Simple Word Boundaries  The class of <word_character> includes all Alphabetic
// values from the Unicode character database, from UnicodeData.txt [UData], plus the U+200C
// ZERO WIDTH NON-JOINER and U+200D ZERO WIDTH JOINER.
func IsWordChar(r byte) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '_'
}

func IsECMAWordChar(r byte) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9' || r == '_'
}

// SingletonChar will return the char from the first range without validation.
// It assumes you have checked for IsSingleton or IsSingletonInverse and will panic given bad input
func (c CharSet) SingletonChar() byte {
	return c.ranges[0].first
}

func (c CharSet) IsSingleton() bool {
	return !c.negate && //negated is multiple chars
		len(c.categories) == 0 && len(c.ranges) == 1 && // multiple ranges and unicode classes represent multiple chars
		c.sub == nil && // subtraction means we've got multiple chars
		c.ranges[0].first == c.ranges[0].last // first and last equal means we're just 1 char
}

func (c CharSet) IsSingletonInverse() bool {
	return c.negate && //same as above, but requires negated
		len(c.categories) == 0 && len(c.ranges) == 1 && // multiple ranges and unicode classes represent multiple chars
		c.sub == nil && // subtraction means we've got multiple chars
		c.ranges[0].first == c.ranges[0].last // first and last equal means we're just 1 char
}

func (c CharSet) IsMergeable() bool {
	return !c.IsNegated() && !c.HasSubtraction()
}

func (c CharSet) IsNegated() bool {
	return c.negate
}

func (c CharSet) HasSubtraction() bool {
	return c.sub != nil
}

func (c CharSet) IsEmpty() bool {
	return len(c.ranges) == 0 && len(c.categories) == 0 && c.sub == nil
}

func (c *CharSet) addDigit(ecma, negate bool, pattern string) {
	if ecma {
		if negate {
			c.addRanges(NotECMADigitClass().ranges)
		} else {
			c.addRanges(ECMADigitClass().ranges)
		}
	} else {
		c.addCategories(category{cat: "Nd", negate: negate})
	}
}

func (c *CharSet) addChar(ch byte) {
	c.addRange(ch, ch)
}

func (c *CharSet) addSpace(ecma, re2, negate bool) {
	if ecma {
		if negate {
			c.addRanges(NotECMASpaceClass().ranges)
		} else {
			c.addRanges(ECMASpaceClass().ranges)
		}
	} else if re2 {
		if negate {
			c.addRanges(NotRE2SpaceClass().ranges)
		} else {
			c.addRanges(RE2SpaceClass().ranges)
		}
	} else {
		c.addCategories(category{cat: spaceCategoryText, negate: negate})
	}
}

func (c *CharSet) addWord(ecma, negate bool) {
	if ecma {
		if negate {
			c.addRanges(NotECMAWordClass().ranges)
		} else {
			c.addRanges(ECMAWordClass().ranges)
		}
	} else {
		c.addCategories(category{cat: wordCategoryText, negate: negate})
	}
}

// Add set ranges and categories into ours -- no deduping or anything
func (c *CharSet) addSet(set CharSet) {
	if c.anything {
		return
	}
	if set.anything {
		c.makeAnything()
		return
	}
	// just append here to prevent double-canon
	c.ranges = append(c.ranges, set.ranges...)
	c.addCategories(set.categories...)
	c.canonicalize()
}

func (c *CharSet) makeAnything() {
	c.anything = true
	c.categories = []category{}
	c.ranges = AnyClass().ranges
}

func (c *CharSet) addCategories(cats ...category) {
	// don't add dupes and remove positive+negative
	if c.anything {
		// if we've had a previous positive+negative group then
		// just return, we're as broad as we can get
		return
	}

	for _, ct := range cats {
		found := false
		for _, ct2 := range c.categories {
			if ct.cat == ct2.cat {
				if ct.negate != ct2.negate {
					// oposite negations...this mean we just
					// take us as anything and move on
					c.makeAnything()
					return
				}
				found = true
				break
			}
		}

		if !found {
			c.categories = append(c.categories, ct)
		}
	}
}

// Merges new ranges to our own
func (c *CharSet) addRanges(ranges []singleRange) {
	if c.anything {
		return
	}
	c.ranges = append(c.ranges, ranges...)
	c.canonicalize()
}

// Merges everything but the new ranges into our own
func (c *CharSet) addNegativeRanges(ranges []singleRange) {
	if c.anything {
		return
	}

	var hi byte

	// convert incoming ranges into opposites, assume they are in order
	for _, r := range ranges {
		if hi < r.first {
			c.ranges = append(c.ranges, singleRange{hi, r.first - 1})
		}
		hi = r.last + 1
	}

	if hi < 0xFF {
		c.ranges = append(c.ranges, singleRange{hi, 0xFF})
	}

	c.canonicalize()
}

func isValidUnicodeCat(catName string) bool {
	_, ok := unicodeCategories[catName]
	return ok
}

func (c *CharSet) addCategory(categoryName string, negate, caseInsensitive bool, pattern string) {
	if !isValidUnicodeCat(categoryName) {
		// unknown unicode category, script, or property "blah"
		panic(fmt.Errorf("Unknown unicode category, script, or property '%v'", categoryName))

	}

	if caseInsensitive && (categoryName == "Ll" || categoryName == "Lu" || categoryName == "Lt") {
		// when RegexOptions.IgnoreCase is specified then {Ll} {Lu} and {Lt} cases should all match
		c.addCategories(
			category{cat: "Ll", negate: negate},
			category{cat: "Lu", negate: negate},
			category{cat: "Lt", negate: negate})
	}
	c.addCategories(category{cat: categoryName, negate: negate})
}

func (c *CharSet) addSubtraction(sub *CharSet) {
	c.sub = sub
}

func (c *CharSet) addRange(chMin, chMax byte) {
	c.ranges = append(c.ranges, singleRange{first: chMin, last: chMax})
	c.canonicalize()
}

func (c *CharSet) addNamedASCII(name string, negate bool) bool {
	var rs []singleRange

	switch name {
	case "alnum":
		rs = []singleRange{singleRange{'0', '9'}, singleRange{'A', 'Z'}, singleRange{'a', 'z'}}
	case "alpha":
		rs = []singleRange{singleRange{'A', 'Z'}, singleRange{'a', 'z'}}
	case "ascii":
		rs = []singleRange{singleRange{0, 0x7f}}
	case "blank":
		rs = []singleRange{singleRange{'\t', '\t'}, singleRange{' ', ' '}}
	case "cntrl":
		rs = []singleRange{singleRange{0, 0x1f}, singleRange{0x7f, 0x7f}}
	case "digit":
		c.addDigit(false, negate, "")
	case "graph":
		rs = []singleRange{singleRange{'!', '~'}}
	case "lower":
		rs = []singleRange{singleRange{'a', 'z'}}
	case "print":
		rs = []singleRange{singleRange{' ', '~'}}
	case "punct": //[!-/:-@[-`{-~]
		rs = []singleRange{singleRange{'!', '/'}, singleRange{':', '@'}, singleRange{'[', '`'}, singleRange{'{', '~'}}
	case "space":
		c.addSpace(true, false, negate)
	case "upper":
		rs = []singleRange{singleRange{'A', 'Z'}}
	case "word":
		c.addWord(true, negate)
	case "xdigit":
		rs = []singleRange{singleRange{'0', '9'}, singleRange{'A', 'F'}, singleRange{'a', 'f'}}
	default:
		return false
	}

	if len(rs) > 0 {
		if negate {
			c.addNegativeRanges(rs)
		} else {
			c.addRanges(rs)
		}
	}

	return true
}

type singleRangeSorter []singleRange

func (p singleRangeSorter) Len() int           { return len(p) }
func (p singleRangeSorter) Less(i, j int) bool { return p[i].first < p[j].first }
func (p singleRangeSorter) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// Logic to reduce a character class to a unique, sorted form.
func (c *CharSet) canonicalize() {
	var i, j int
	var last byte

	//
	// Find and eliminate overlapping or abutting ranges
	//

	if len(c.ranges) > 1 {
		sort.Sort(singleRangeSorter(c.ranges))

		done := false

		for i, j = 1, 0; ; i++ {
			for last = c.ranges[j].last; ; i++ {
				if i == len(c.ranges) || last == 0xFF {
					done = true
					break
				}

				CurrentRange := c.ranges[i]
				if CurrentRange.first > last+1 {
					break
				}

				if last < CurrentRange.last {
					last = CurrentRange.last
				}
			}

			c.ranges[j] = singleRange{first: c.ranges[j].first, last: last}

			j++

			if done {
				break
			}

			if j < i {
				c.ranges[j] = c.ranges[i]
			}
		}

		c.ranges = append(c.ranges[:j], c.ranges[len(c.ranges):]...)
	}
}

// Adds to the class any lowercase versions of characters already
// in the class. Used for case-insensitivity.
func (c *CharSet) addLowercase() {
	if c.anything {
		return
	}
	toAdd := []singleRange{}
	for i := 0; i < len(c.ranges); i++ {
		r := c.ranges[i]
		if r.first == r.last {
			lower := toLowerChar(r.first)
			c.ranges[i] = singleRange{first: lower, last: lower}
		} else {
			toAdd = append(toAdd, r)
		}
	}

	for _, r := range toAdd {
		c.addLowercaseRange(r.first, r.last)
	}
	c.canonicalize()
}

/**************************************************************************
    Let U be the set of Unicode character values and let L be the lowercase
    function, mapping from U to U. To perform case insensitive matching of
    character sets, we need to be able to map an interval I in U, say

        I = [chMin, chMax] = { ch : chMin <= ch <= chMax }

    to a set A such that A contains L(I) and A is contained in the union of
    I and L(I).

    The table below partitions U into intervals on which L is non-decreasing.
    Thus, for any interval J = [a, b] contained in one of these intervals,
    L(J) is contained in [L(a), L(b)].

    It is also true that for any such J, [L(a), L(b)] is contained in the
    union of J and L(J). This does not follow from L being non-decreasing on
    these intervals. It follows from the nature of the L on each interval.
    On each interval, L has one of the following forms:

        (1) L(ch) = constant            (LowercaseSet)
        (2) L(ch) = ch + offset         (LowercaseAdd)
        (3) L(ch) = ch | 1              (LowercaseBor)
        (4) L(ch) = ch + (ch & 1)       (LowercaseBad)

    It is easy to verify that for any of these forms [L(a), L(b)] is
    contained in the union of [a, b] and L([a, b]).
***************************************************************************/

const (
	LowercaseSet = 0 // Set to arg.
	LowercaseAdd = 1 // Add arg.
	LowercaseBor = 2 // Bitwise or with 1.
	LowercaseBad = 3 // Bitwise and with 1 and add original.
)

type lcMap struct {
	chMin, chMax byte
	op, data     int32
}

var lcTable = []lcMap{
	lcMap{'\u0041', '\u005A', LowercaseAdd, 32},
	lcMap{'\u00C0', '\u00DE', LowercaseAdd, 32},
}

func (c *CharSet) addLowercaseRange(chMin, chMax byte) {
	var i, iMax, iMid int
	var chMinT, chMaxT byte
	var lc lcMap

	for i, iMax = 0, len(lcTable); i < iMax; {
		iMid = (i + iMax) / 2
		if lcTable[iMid].chMax < chMin {
			i = iMid + 1
		} else {
			iMax = iMid
		}
	}

	for ; i < len(lcTable); i++ {
		lc = lcTable[i]
		if lc.chMin > chMax {
			return
		}
		chMinT = lc.chMin
		if chMinT < chMin {
			chMinT = chMin
		}

		chMaxT = lc.chMax
		if chMaxT > chMax {
			chMaxT = chMax
		}

		switch lc.op {
		case LowercaseSet:
			chMinT = byte(lc.data)
			chMaxT = byte(lc.data)
			break
		case LowercaseAdd:
			chMinT += byte(lc.data)
			chMaxT += byte(lc.data)
			break
		case LowercaseBor:
			chMinT |= 1
			chMaxT |= 1
			break
		case LowercaseBad:
			chMinT += (chMinT & 1)
			chMaxT += (chMaxT & 1)
			break
		}

		if chMinT < chMin || chMaxT > chMax {
			c.addRange(chMinT, chMaxT)
		}
	}
}
