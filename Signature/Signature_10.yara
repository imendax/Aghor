rule signature_10
{
	meta:
		author = "0xlsd"
		sample = "7c326fa7b55177594c02e7892f75c4b865798c05f6f26cea0ee35c2febdf6bee"
	
	
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
			96
			40
		}
	
	condition:
		any of them
	
}
