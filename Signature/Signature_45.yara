rule signature_45
{
	meta:
		author = "0xlsd"
		sample = "224be639bf2234b0b353abc3391ed0a9d1d13fa91d67c527d8c9aaa1a8e78d81"
	
	
	strings:
		$string_1 = {
			65 6D
			65 6E
			74 ??
			42
			79 ??
			61
			67 4E
			61
			6D
			65 28 22
			68 65 61 64 22
			29 5B ??
			5D
			3B 0A
			09 69 ??
			28 21
			68 65 61 64 29
			7B ??
		}
	
	condition:
		any of them
	
}
