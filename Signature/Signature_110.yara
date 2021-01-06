rule signature_110
{
	meta:
		author = "0xlsd"
		sample = "745cd82767daddc17d78651bf261036320638225f8242bbe7b149ad6ec114595"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			FA
			6F
			C1 B7 ?? ?? ?? ?? BE
			0E
			AF
		}
	
	condition:
		any of them
	
}
