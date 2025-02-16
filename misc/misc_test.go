package misc_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/archaron/go-yubiserv/misc"
)

const testPattern = "0123456789_{}"

func Test_ModHexToHex(t *testing.T) {
	t.Parallel()
	t.Run("Must decode valid string", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "2f5d71a4915dec304aa13ccf97bb0dbb", misc.ModHexToHex("dvgtiblfkbgturecfllberrvkinnctnn"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		t.Parallel()

		testString := "1234567890!@#$%^&*()_+=]\\[';/.,qwyopaszxm<>?"

		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			misc.ModHexToHex(testString),
		)
	})
}

func Test_Hex2ModHex(t *testing.T) {
	t.Parallel()
	t.Run("Must decode valid string", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "dvgtiblfkbgturecfllberrvkinnctnn", misc.HexToModHex("2f5d71a4915dec304aa13ccf97bb0dbb"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		t.Parallel()

		testString := "qwrtyuiop[]shjkl;'\\zxvnm,./"

		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			misc.HexToModHex(testString),
		)
	})
}

func Test_DvorakToModHex(t *testing.T) {
	t.Parallel()
	t.Run("Must decode valid string", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "cbdefghijklnrtuv", misc.DvorakToModHex("jxe.uidchtnbpygk"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		t.Parallel()

		testString := testPattern

		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			misc.DvorakToModHex(testString),
		)
	})
}

func Test_ModHexToDvorak(t *testing.T) {
	t.Parallel()
	t.Run("Must decode valid string", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, "jxe.uidchtnbpygk", misc.ModHexToDvorak("cbdefghijklnrtuv"))
	})

	t.Run("Must replace invalid chars with 0", func(t *testing.T) {
		t.Parallel()

		testString := testPattern

		require.Equal(t,
			strings.Repeat("\000", len(testString)),
			misc.ModHexToDvorak(testString),
		)
	})
}

func Test_Rand(t *testing.T) { //nolint:tparallel
	var (
		err          error
		rand1, rand2 []byte
	)

	t.Parallel()

	t.Run("Must generate random bytes", func(t *testing.T) { //nolint:paralleltest
		rand1, err = misc.Rand(10)
		require.NoError(t, err)
		require.Len(t, rand1, 10)
	})

	t.Run("Must generate other random bytes", func(t *testing.T) { //nolint:paralleltest
		rand2, err = misc.Rand(10)
		require.NoError(t, err)
		require.Len(t, rand2, 10)
		require.NotEqual(t, rand1, rand2)
	})
}

func Test_HexRand(t *testing.T) { //nolint:tparallel
	var (
		err          error
		rand1, rand2 string
	)

	t.Parallel()

	t.Run("Must generate random hex-string", func(t *testing.T) { //nolint:paralleltest
		rand1, err = misc.HexRand(10)
		require.NoError(t, err)
		require.Len(t, rand1, 20)
	})

	t.Run("Must generate other random hex-string", func(t *testing.T) { //nolint:paralleltest
		rand2, err = misc.HexRand(10)
		require.NoError(t, err)
		require.Len(t, rand2, 20)
		require.NotEqual(t, rand1, rand2)
	})
}

func Test_IsAlphaNum(t *testing.T) {
	t.Parallel()

	t.Run("Must be alphanum", func(t *testing.T) {
		t.Parallel()
		require.True(t, misc.IsAlphaNum("ThisIsAlphaNumeric123StringOK"))
	})

	t.Run("Must not be alphanum", func(t *testing.T) {
		t.Parallel()
		require.False(t, misc.IsAlphaNum("А это нихрена не Alpanumeric!"))
	})
}

func Test_IsDvorakModHex(t *testing.T) {
	t.Parallel()

	t.Run("Must be DvorakModhex", func(t *testing.T) {
		t.Parallel()
		require.True(t, misc.IsDvorakModHex("idjxuce.htpypy.nbgk"))
	})

	t.Run("Must not be DvorakModhex", func(t *testing.T) {
		t.Parallel()
		require.False(t, misc.IsDvorakModHex("жопаежаужажужалицы"))
	})
}

func Test_IsModHex(t *testing.T) {
	t.Parallel()

	t.Run("Must be Modhex", func(t *testing.T) {
		t.Parallel()
		require.True(t, misc.IsModHex("dvgtiblfkbgturecfllberrvkinnctnn"))
	})

	t.Run("Must not be Modhex", func(t *testing.T) {
		t.Parallel()
		require.False(t, misc.IsModHex("312312dsfdfg319c5743"))
	})
}
