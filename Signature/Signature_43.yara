rule signature_43
{
	meta:
		author = "0xlsd"
		sample = "64336735519712a5d2e70b192e48cab89adb69b66457a0ed111b3bc1626e6452"
	
	
	strings:
		$string_1 = {
			CD 8A
			50
			98
			C4 8A ?? ?? ?? ??
			D0 98 ?? ?? ?? ??
			CD 8A
			52
			69 63 ?? 39 87 CD 8A
			00 00
			00 00
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
