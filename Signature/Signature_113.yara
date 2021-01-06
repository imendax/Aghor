rule signature_113
{
	meta:
		author = "0xlsd"
		sample = "34863a030a91b0948801311d0ec5246d1e91709f52e1cd0db4ddd00cf5ac6048"
	
	
	strings:
		$string_1 = {
			20 72 ??
			6E
			20 75 ??
			64 65 72 ??
			57
			69 6E ?? 32 0A 0D 24
			37
			00 00
			00 00
			00 00
			00 00
			50
			45
			00 00
			4C
			01 04 00
			FD
			AE
			44
			44
		}
	
	condition:
		any of them
	
}
