rule signature_118
{
	meta:
		author = "0xlsd"
		sample = "359b6f1803f2369fe98f76770863ecce1fcab6da884a03df575e5ba2501a24bf"
	
	
	strings:
		$string_1 = {
			00 00
			00 02
			00 00
			00 FF
			FF 00
			00 B8 ?? ?? ?? ??
			00 00
			00 0A
			00 00
			00 00
			00 00
			00 0E
			1F
			BA 0E 00 B4 09
			CD 21
		}
	
	condition:
		any of them
	
}
