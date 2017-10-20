package challenge20

import (
	"testing"
	"strings"
)

var plaintexts []string = []string{
	"i'm rated \"R\"...this is a warning, ya better void / P",
	"cuz I came back to attack others in spite- / Strike l",
	"but don't be afraid in the dark, in a park / Not a sc",
	"ya tremble like a alcoholic, muscles tighten up / Wha",
	"suddenly you feel like your in a horror flick / You g",
	"music's the clue, when I come your warned / Apocalyps",
	"haven't you ever heard of a MC-murderer? / This is th",
	"death wish, so come on, step to this / Hysterical ide",
	"friday the thirteenth, walking down Elm Street / You ",
	"this is off limits, so your visions are blurry / All ",
	"terror in the styles, never error-files / Indeed I'm ",
	"for those that oppose to be level or next to this / I",
	"worse than a nightmare, you don't have to sleep a win",
	"flashbacks interfere, ya start to hear: / The R-A-K-I",
	"then the beat is hysterical / That makes Eric go get ",
	"soon the lyrical format is superior / Faces of death ",
	"mC's decaying, cuz they never stayed / The scene of a",
	"the fiend of a rhyme on the mic that you know / It's ",
	"melodies-unmakable, pattern-unescapable / A horn if w",
	"i bless the child, the earth, the gods and bomb the r",
	"hazardous to your health so be friendly / A matter of",
	"shake 'till your clear, make it disappear, make the n",
	"if not, my soul'll release! / The scene is recreated,",
	"cuz your about to see a disastrous sight / A performa",
	"lyrics of fury! A fearified freestyle! / The \"R\" is i",
	"make sure the system's loud when I mention / Phrases ",
	"you want to hear some sounds that not only pounds but",
	"then nonchalantly tell you what it mean to me / Stric",
	"and I don't care if the whole crowd's a witness! / I'",
	"program into the speed of the rhyme, prepare to start",
	"musical madness MC ever made, see it's / Now an emerg",
	"open your mind, you will find every word'll be / Furi",
	"battle's tempting...whatever suits ya! / For words th",
	"you think you're ruffer, then suffer the consequences",
	"i wake ya with hundreds of thousands of volts / Mic-t",
	"novocain ease the pain it might save him / If not, Er",
	"yo Rakim, what's up? / Yo, I'm doing the knowledge, E",
	"well, check this out, since Norby Walters is our agen",
	"kara Lewis is our agent, word up / Zakia and 4th and ",
	"okay, so who we rollin' with then? We rollin' with Ru",
	"check this out, since we talking over / This def beat",
	"i wanna hear some of them def rhymes, you know what I",
	"thinkin' of a master plan / 'Cuz ain't nuthin' but sw",
	"so I dig into my pocket, all my money is spent / So I",
	"so I start my mission, leave my residence / Thinkin' ",
	"i need money, I used to be a stick-up kid / So I thin",
	"i used to roll up, this is a hold up, ain't nuthin' f",
	"but now I learned to earn 'cuz I'm righteous / I feel",
	"search for a nine to five, if I strive / Then maybe I",
	"so I walk up the street whistlin' this / Feelin' out ",
	"a pen and a paper, a stereo, a tape of / Me and Eric ",
	"fish, which is my favorite dish / But without no mone",
	"'cuz i don't like to dream about gettin' paid / so I ",
	"so now to test to see if I got pull / Hit the studio,",
	"rakim, check this out, yo / You go to your girl house",
	"'cause my girl is definitely mad / 'cause it took us ",
	"yo, I hear what you're saying / So let's just pump th",
	"and count our money / Yo, well check this out, yo Eli",
	"turn down the bass down / And let the beat just keep ",
	"and we outta here / Yo, what happened to peace? / Pea",
}

func TestCrack(t *testing.T) {
	cracked := Crack()

	for i, pt := range plaintexts {
		if strings.ToLower(pt) != strings.ToLower(string(cracked[i])) {
			t.Fail()
		}
	}
}
