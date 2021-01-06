rule signature_77
{
	meta:
		author = "0xlsd"
		sample = "1ecfe4b511b8597050c7fe68dabe4dc2e3e0e38a531ea74ee17e3f0a23578c4f"
	
	
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
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
