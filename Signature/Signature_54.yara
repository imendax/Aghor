rule signature_54
{
	meta:
		author = "0xlsd"
		sample = "12849756691c646e75dfd8770cf341b933e420319081be5ca1e4a5acb5d4d82c"
	
	
	strings:
		$string_1 = {
			00 EF
			BE C9 3A EE 9D
			B7 42
			0C BA
			14 00
			00 00
			57
			00 49 ??
			4E
			00 44 00 ??
			00 57 ??
			53
			00 00
			00 16
			00 40 ??
			31 00
			00 00
		}
	
	condition:
		any of them
	
}
