public class Computer
{
	public static void main(String[] args)
	{
		double x = 0;
		for (int i = 1; i < 101; i++) {
			x = compute(x);
			System.out.println(i+": "+x);
		}
	}
	public static double compute(double x)
	{
		return Math.pow(2.71828183, 1.2*(x-1));
	}
}