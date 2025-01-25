package misc

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ModHexToHex(t *testing.T) {
	t.Run("Must decode valid string", func(t *testing.T) {
		require.Equal(t, "2f5d71a4915dec304aa13ccf97bb0dbb", ModHexToHex("dvgtiblfkbgturecfllberrvkinnctnn"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		testString := "1234567890!@#$%^&*()_+=]\\[';/.,qwyopaszxm<>?"
		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			ModHexToHex(testString),
		)
	})
}

func Test_Hex2ModHex(t *testing.T) {
	t.Run("Must decode valid string", func(t *testing.T) {
		require.Equal(t, "dvgtiblfkbgturecfllberrvkinnctnn", HexToModHex("2f5d71a4915dec304aa13ccf97bb0dbb"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		testString := "qwrtyuiop[]shjkl;'\\zxvnm,./"
		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			HexToModHex(testString),
		)
	})
}

func Test_DvorakToModHex(t *testing.T) {
	t.Run("Must decode valid string", func(t *testing.T) {
		require.Equal(t, "cbdefghijklnrtuv", DvorakToModHex("jxe.uidchtnbpygk"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		testString := "0123456789_{}"
		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			DvorakToModHex(testString),
		)
	})
}

func Test_ModHexToDvorak(t *testing.T) {
	t.Run("Must decode valid string", func(t *testing.T) {
		require.Equal(t, "jxe.uidchtnbpygk", ModHexToDvorak("cbdefghijklnrtuv"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		testString := "0123456789_{}"
		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			ModHexToDvorak(testString),
		)
	})
}

func Test_Rand(t *testing.T) {
	var err error
	var rand1, rand2 []byte

	t.Run("Must generate random bytes", func(t *testing.T) {
		rand1, err = Rand(10)
		require.NoError(t, err)
		require.Len(t, rand1, 10)
	})

	t.Run("Must generate other random bytes", func(t *testing.T) {
		rand2, err = Rand(10)
		require.NoError(t, err)
		require.Len(t, rand2, 10)
		require.NotEqual(t, rand1, rand2)
	})
}

func Test_HexRand(t *testing.T) {
	var err error
	var rand1, rand2 string

	t.Run("Must generate random hex-string", func(t *testing.T) {
		rand1, err = HexRand(10)
		require.NoError(t, err)
		require.Len(t, rand1, 20)
	})

	t.Run("Must generate other random hex-string", func(t *testing.T) {
		rand2, err = HexRand(10)
		require.NoError(t, err)
		require.Len(t, rand2, 20)
		require.NotEqual(t, rand1, rand2)
	})
}

func Test_IsAlphaNum(t *testing.T) {
	t.Run("Must be alphanum", func(t *testing.T) {
		require.True(t, IsAlphaNum("ThisIsAlphaNumeric123StringOK"))
	})
	t.Run("Must not be alphanum", func(t *testing.T) {
		require.False(t, IsAlphaNum("А это нихрена не Alpanumeric!"))
	})
}

func Test_IsDvorakModHex(t *testing.T) {
	t.Run("Must be DvorakModhex", func(t *testing.T) {
		require.True(t, IsDvorakModHex("idjxuce.htpypy.nbgk"))
	})

	t.Run("Must not be DvorakModhex", func(t *testing.T) {
		require.False(t, IsDvorakModHex("жопаежаужажужалицы"))
	})
}

func Test_IsModHex(t *testing.T) {
	t.Run("Must be Modhex", func(t *testing.T) {
		require.True(t, IsModHex("dvgtiblfkbgturecfllberrvkinnctnn"))
	})

	t.Run("Must not be Modhex", func(t *testing.T) {
		require.False(t, IsModHex("312312dsfdfg319c5743"))
	})
}
