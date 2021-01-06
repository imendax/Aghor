rule signature_90
{
	meta:
		author = "0xlsd"
		sample = "138ad0b7d4f6f64be0b7a6227a794662272858a1a2f5665b6c5f9a4e0f282e85"
	
	
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
			31 B8 ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
