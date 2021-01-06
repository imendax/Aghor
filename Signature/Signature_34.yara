rule signature_34
{
	meta:
		author = "0xlsd"
		sample = "3383fcf7dbb3f222a2195461f05f2f3285bd1c2d82e2c1451eaca709689aa815"
	
	
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
			95
			A4
		}
	
	condition:
		any of them
	
}
