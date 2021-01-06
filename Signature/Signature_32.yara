rule signature_32
{
	meta:
		author = "0xlsd"
		sample = "c1531795119275b7deda8ff3beae5db0319bbbf715d7f2d203d17612801d798f"
	
	
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
		}
	
	condition:
		any of them
	
}
