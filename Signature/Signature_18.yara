rule signature_18
{
	meta:
		author = "0xlsd"
		sample = "246e63e21c94dd3feb0980f3b78103d69c22dd83a279f58b53dd06e5d137425c"
	
	
	strings:
		$string_1 = {
			CD 65
			36 3C 7C
			4A
			17
			AA
			FB
			25 72 10 DD 96
			02 13
			9E
			45
			71 ??
			D9 71 ??
			5F
			F9
			29 DF
			C5 5F ??
		}
	
	condition:
		any of them
	
}
