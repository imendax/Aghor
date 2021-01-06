rule signature_9
{
	meta:
		author = "0xlsd"
		sample = "0cb1d9dd01c4d5d4164fd2c8a643ad9b28b04547e953c010e89239e259749d14"
	
	
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
			EF
		}
	
	condition:
		any of them
	
}
