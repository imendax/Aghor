rule signature_74
{
	meta:
		author = "0xlsd"
		sample = "1276382fdcd8be6343515425cf3ced6e2e11ce42fb347954d24a33966182f9e5"
	
	
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
			01 07
			00 28
			1A E4
			50
		}
	
	condition:
		any of them
	
}
