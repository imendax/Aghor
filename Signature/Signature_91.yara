rule signature_91
{
	meta:
		author = "0xlsd"
		sample = "5df2c90942c88c04c239406b6d9699e8137629c719d082cb6579dc75982137f1"
	
	
	strings:
		$signature__1 = {
			20 72 ??
			6E
			20 69 ??
			20 44 4F ??
			20 6D ??
			64 65 2E 0D 0D 0A 24 00
			00 00
			00 00
			00 00
			3D 6F FD 37 79
			0E
			93
			64 79 ??
			93
		}
	
	condition:
		any of them
	
}
