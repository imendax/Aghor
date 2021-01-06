rule signature_38
{
	meta:
		author = "0xlsd"
		sample = "355509527d6ad48c4545ade71defc555eac9736c745cf3bd0e48d8e90b93fe62"
	
	
	strings:
		$string_1 = {
			CD 8A
			50
			98
			C4 8A ?? ?? ?? ??
			D0 98 ?? ?? ?? ??
			CD 8A
			52
			69 63 ?? 39 87 CD 8A
			00 00
			00 00
			00 00
			00 00
			50
			45
			00 00
			4C
		}
	
	condition:
		any of them
	
}
