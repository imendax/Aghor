rule signature_136
{
	meta:
		author = "0xlsd"
		sample = "a8c24d4bb4048d5d01fbba8f74a90df030e1e9cdc8c6061c2d83300f212a1b97"
	
	
	strings:
		$stirng_1 = {
			3D 0B A8 5C 3C
			0B C3
			5C
			3D 0B B6 0E BE
			0B A9 ?? ?? ?? ??
			5C
			3D 0B A9 5C 3D
			0B B6 ?? ?? ?? ??
			5C
			3D 0B 52 69 63
		}
	
	condition:
		any of them
	
}
