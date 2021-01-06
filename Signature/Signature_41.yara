rule signature_41
{
	meta:
		author = "0xlsd"
		sample = "b56876b4dadf00490224eaf63e98972862447812054726ba91f2168d1c871981"
	
	
	strings:
		$string_1 = {
			0E
			01 0B
			01 02
			32 00
			C6 04 00 00
			CC
			00 00
			00 00
			00 00
			80 13 00
			00 00
			10 00
			00 00
			E0 04
			00 00
			00 40 ??
			00 10
			00 00
			00 02
		}
	
	condition:
		any of them
	
}
