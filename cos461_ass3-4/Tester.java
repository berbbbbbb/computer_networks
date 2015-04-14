import java.util.*;

public class Tester
{
	private int x, y;
	
	public static void main(String[] args)
	{
		System.out.println("Hello baba.");
		Tester temp = new Tester(6, 7);
		Tester temp2 = new Tester(7, 8);
		System.out.println(temp.get_sum());
	}
	
	public Tester(int xx, int yy)
	{
		x = xx;
		y = yy;
	}
	
	public int get_sum()
	{
		//System.out.println(x + y);
		return x+y;
	}
}