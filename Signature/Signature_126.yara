rule signature_126
{
	meta:
		author = "0xlsd"
		sample = "d9210557d3812466c7de7843de7196931ad00131bf3808966de297733a154d0e"
	
	
	strings:
		$string_1 = {
			56
			15 E3 1F 09 15
			28 10
			56
			15 E3 1F 0B 15
			3B 10
			56
			15 20 10 57 15
			10 12
			56
			15 A3 0C 58 15
			38 10
			56
			15 16 36 5C 15
			B0 10
		}
	
	condition:
		any of them
	
}
