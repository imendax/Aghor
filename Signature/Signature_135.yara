rule signature_135
{
	meta:
		author = "0xlsd"
		sample = "a086790a926955b0e1a23e8043bd385cd04eb76347e2b94da152972dffd9042b"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 02
			32 00
			00 04 00
			00 1C 00
			00 00
			00 00
			00 F0
			12 00
			00 00
			10 00
			00 00
			20 04 00
			00 00
			40
			00 00
			10 00
			00 00
		}
	
	condition:
		any of them
	
}
