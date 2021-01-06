rule signature_81
{
	meta:
		author = "0xlsd"
		sample = "c89568812601f5d3d8155807adc61a6af15d820bc353254185760a867f8ed5ea"
	
	
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
			01 02
			00 00
			00 00
		}
	
	condition:
		any of them
	
}
