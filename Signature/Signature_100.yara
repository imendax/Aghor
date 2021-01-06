rule signature_100
{
	meta:
		author = "0xlsd"
		sample = "c0615af357bc5f3ecffc1bc481e44760cf6fea74359423b33fba4befb2ebadff"
	
	
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
			68 AF 74 1E 2C
			CE
			1A 4D ??
			CE
		}
	
	condition:
		any of them
	
}
