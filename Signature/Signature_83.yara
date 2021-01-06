rule signature_83
{
	meta:
		author = "0xlsd"
		sample = "ba5987b5646eb61b246a99ebf002140917925de0629164bea7072a7e6c66f8f1"
	
	
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
			50
			45
			00 00
			4C
			01 03
			00 55 ??
		}
	
	condition:
		any of them
	
}
