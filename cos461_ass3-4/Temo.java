public class Temo
{
	public static void main(String[] args) 
	{
		int[] arr = new int[10];
		function(arr);
		for (int i = 0; i < arr.length; i++)
			System.out.println(arr[i]);
	}
	public static int function(int[] arr)
	{
		arr[1] = arr[2];
		arr[2] = 5;
		return 1;
	}
}