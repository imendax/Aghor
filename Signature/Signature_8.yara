rule signature_8
{
	meta:
		author = "0xlsd"
		sample = "ec8a3a39b091a80bc26e3ea68baf9437fa52b70ad6f2e9dc14edc3ddc13347d9"
	
	
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
			1C 19
		}
	
	condition:
		any of them
	
}
