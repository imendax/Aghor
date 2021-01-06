rule signature_15
{
	meta:
		author = "0xlsd"
		sample = "8b77ce8598009e0cc925eb527e43cd7d246aadaf4ab11ad0568e3815c9150979"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 75 ??
			64 65 72 ??
			57
			69 6E ?? 32 0D 0A 24
			37
			00 00
			00 00
			50
			45
			00 00
			4C
		}
	
	condition:
		any of them
	
}
