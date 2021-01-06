rule signature_94
{
	meta:
		author = "0xlsd"
		sample = "f547e6e64ab617edc6f5fd6bca2fdc6c162cd9602c1309dae75ac8b81aec95e9"
	
	
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
			F3 84 77 ??
			B7 E5
			19 9B ?? ?? ?? ??
		}
	
	condition:
		any of them
	
}
