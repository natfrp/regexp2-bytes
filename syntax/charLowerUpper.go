package syntax

import "unicode"

func toLowerChar(ch byte) byte {
	return byte(unicode.ToLower(rune(ch)))
}

func toUpperChar(ch byte) byte {
	return byte(unicode.ToUpper(rune(ch)))
}
