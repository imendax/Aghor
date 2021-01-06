rule signature_4
{
	meta:
		author = "0xlsd"
		sample = "2c053fa74cb154a2027c30060a08f7777134b225e941ff6f0282e627ee2a157f"
	
	
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
			72 ??
		}
	
	condition:
		any of them
	
}
