rule signature_92
{
	meta:
		author = "0xlsd"
		sample = "7899ac8c48f07a991c48cb539f5ff0914db3cceed8f7b1175c95239fb5ce688e"
	
	
	strings:
		$string_1 = {
			8C 4E ??
			56
			86 51 ??
			53
			8E 46 ??
			35 9C 3B 60 BC
		}
	
	condition:
		any of them
	
}
