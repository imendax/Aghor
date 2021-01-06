rule signature_13
{
	meta:
		author = "0xlsd"
		sample = "02157bf54cec981e177074c62c09dd95f5860a90cd50f0b8f6c59456c02cf4ad"
	
	
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
			C3
		}
	
	condition:
		any of them
	
}
