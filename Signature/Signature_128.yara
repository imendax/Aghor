rule signature_128
{
	meta:
		author = "0xlsd"
		sample = "c03fce302a37b5b7fcf45ede23b30dc4909376c2b23d05fc51fc82485f1226e6"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 02
			32 00
			60
			00 00
			00 DA
			03 00
			00 00
			00 00
			E0 41
			03 00
			00 40 ??
			00 00
			10 00
			00 00
			00 40 ??
			00 10
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
