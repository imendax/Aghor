rule signature_114
{
	meta:
		author = "0xlsd"
		sample = "f600bb6c770514c47e87764d9ce360972883c3729a3060337bf22cccb9190b7f"
	
	
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
