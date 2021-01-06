rule signature_144
{
	meta:
		author = "0xlsd"
		sample = "d1ff5552be5af48039838e3ef8479b349add0aaf7ceb67ad2a50b84893b5c30a"
	
	
	strings:
		$string_1 = {
			9D
			7E ??
			29 C0
			7E ??
			26 9D
			7E ??
			26 9C
			7E ??
			26 9D
			7E ??
			29 C2
			7E ??
			26 9D
			7E ??
			29 C3
			7E ??
			26 9D
			7E ??
			29 C7
			7E ??
		}
	
	condition:
		any of them
	
}
