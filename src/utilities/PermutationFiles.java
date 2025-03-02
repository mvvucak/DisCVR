package utilities;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.Math;
import java.net.URL;



/**
 * Splits a large file contains k-mers and their counts into a number of smaller files so that k-mers
 * are grouped in the files according to their first letters (prefix). 
 * E,g. Letter Set ={ 'A','C','G','T'} and prefix length= 4. 
 * Number of permutations= 4^4 = 256 different prefixes.
 * All k-mers starts AAAA in one file and all k-mers start with TTTT in another file and so on.
 * 
 */
public class PermutationFiles {
	
	public String [] permsArray; //to hold the permutations
	public static int permPosition; //to index the permutation array
	
	/**
	 * Constructor
	 * @param k: defines the length of the word
	 * @param alphabetSet: defines the set of letters
	 */
	public PermutationFiles (int k, int alphabetSet){   
		//calculate the number of permutations
		int permArraySize = (int)Math.pow((double)alphabetSet, (double)k);
		permsArray = new String [permArraySize];
		permPosition =0;
	}
	
	public int getPermsArraySize(){
		return permsArray.length;
	}	
	public String [] getPermsArray(){
		return permsArray;
	}
	
	//splits the db k-mers file into smaller files. 
	public String printsToDbPermsFiles(String dbFileName, String fileNamePrefix, String type, String dbOption, int permLen, String [] allPerms) {
		String result="======================================================================\n";
		/* variables to print out information about the contents of the input file. */
		long lines = 0; //count lines in the file which corresponds to the number of different kmers in the file
		long totalKmersCounts =0;//count the total number of kmers in the file by summing up the kmers counts
		
		try	{
			BufferedReader in = null;			
			if(dbOption.equalsIgnoreCase("BuiltInDB")){
			  URL dbFileURL = ClassLoader.getSystemResource(dbFileName);
			  in = new BufferedReader(new InputStreamReader(dbFileURL.openStream()));			  
			}
			if(dbOption.equalsIgnoreCase("customisedDB")){
			  in = new BufferedReader (new FileReader(dbFileName));
			  
			}
			boolean ok = false; //signals the start of a new file
			String permStr = "";
				        		
			PrintWriter pw = null;
			String line;
			while ((line = in.readLine())!= null){
				/*counts the lines and adds K-mers counts*/
				lines++;
				String words [] = line.split("\t");
				long d = (Long.valueOf(words[1])).longValue();	 
				totalKmersCounts = totalKmersCounts + d;
				
				/*prints the line to a file */
				String perm = line.substring(0,permLen); //get the first characters with the length of the word
					                
				if(!ok)	{ //file is not created 
					String permsFile =fileNamePrefix+(perm);
					pw =  new PrintWriter(new BufferedWriter(new FileWriter(permsFile))); 
					permStr = perm;
					ok = true;	                	
				}
				if(!perm.equalsIgnoreCase(permStr)&& ok) {//file already exists and is open but the perm is different
					pw.close(); //close current file and create another one to write the new k-mer to
					String permsFile =fileNamePrefix+(perm);
					pw =  new PrintWriter(new BufferedWriter(new FileWriter(permsFile)));
					permStr = perm;	            	   
				}
				if(perm.equalsIgnoreCase(permStr)&& ok) {//file already exists, open and the perm is not different
					pw.println(line); //add the new k-mer to the file
				}
			 }
					            
			 pw.close();
			 in.close();	           
					    
			 		          
			result=result+"There are ("+String.format("%,d",lines)+") distinct k-mers in the ";
			if (type=="s"){
				result=result+"sample file.\n";					  
			}
			if (type=="db"){
				result=result+"database.\n";
			}
			result=result+"The total number of their counts is ("+String.format("%,d",totalKmersCounts)+")\n\n ";
		} 
		catch (IOException e){
			System.out.println("Error reading/writing to files");
		}
		return result;
	}	
	
    //splits the sample k-mers into smaller files 
	public String printsToSamplePermsFiles(String fileName, String dir,String type, int permLen, String [] allPerms) {
		String result="==============================================================\n";
		String fileNamePrefix = dir+type+"Kmers_"; //prefix for all file names
			
		/* variables to print out information about the contents of the input file. */
		long lines = 0; //count lines in the file which corresponds to the number of different kmers in the file
		long totalKmersCounts =0;//count the total number of kmers in the file by summing up the kmers counts
			
		try (BufferedReader in = new BufferedReader(new FileReader(fileName))){
			boolean ok = false; //signals the start of a new file
		    String permStr = "";
		        		
		    PrintWriter pw = null;
			String line;
			while ((line = in.readLine())!= null) {
				/*counts the lines and adds K-mers counts*/
			    lines++;
			    String words [] = line.split("\t");
			    long d = (Long.valueOf(words[1])).longValue();	 
			    totalKmersCounts = totalKmersCounts + d;
			                
			    /*prints the line to a file */
			    String perm = line.substring(0,permLen); //get the first characters with the length of the word
			    if(!ok)	{//file is not created 
			    	String permsFile =fileNamePrefix+(perm);
			        pw =  new PrintWriter(new BufferedWriter(new FileWriter(permsFile))); 
			        permStr = perm;
			        ok = true;	                	
			    }
			    if(!perm.equalsIgnoreCase(permStr)&& ok) {//file already exists and is open but the perm is different
			    	pw.close(); //close current file and create another one to write the new k-mer to
			        String permsFile =fileNamePrefix+(perm);
			        pw =  new PrintWriter(new BufferedWriter(new FileWriter(permsFile)));
			        permStr = perm;	            	   
			     }
			     if(perm.equalsIgnoreCase(permStr)&& ok) {//file already exists, open and the perm is not different
			    	 pw.println(line); //add the new k-mer to the file
			     }
			 }  
			 pw.close();
			 in.close();	           
			    
			        
			 result=result+"There are "+lines+" distinct kmers in the ";
			 if (type=="s")
			    result=result+"sample file.\n";
			  if (type=="db")
			    result=result+"database.\n";
			  result=result+"The total number of their counts in the file is:  "+totalKmersCounts+"\n\n ";
			} 
			catch (IOException e){
				System.out.println("Error reading/writing to files");
			}
			return result;
	}
	
	/* The method that prints all possible strings of length k. 
	 * It is mainly a wrapper over recursive function printAllKLengthRec()*/   
	
	/**
	 * @param set: the set of letters 
	 * @param k: the length of words
	 * @param perms: an array to hold all permutations
	 * This method generates all possible words of length k made from the set. 
	 * It mainly calls the recursive function printAllKLengthRec()
	 */
	public void printAllKLength(char set[], int k, String[] perms) 	{
	
        int n = set.length;          
        printAllKLengthRec(set, "", n, k,perms);       
        
    } 
    
	/**
	 * @param set: the set of letters
	 * @param prefix: the word to be added to the array
	 * @param n: the length of the set
	 * @param k: the length of the word
	 * @param perms: an array to hold all the different words
	 * The main recursive method to populate the array with all possible words of length k
	 */
	public void printAllKLengthRec(char set[], String prefix, int n, int k, String [] perms) {
        // Base case: k is 0, print prefix
        if (k == 0) {
            perms[permPosition++]= prefix;  //Add the prefix to the array             
            return;
        }
        
        //add all characters one by one from set recursively
        for (int i = 0; i < n; ++i)
        {
           String newPrefix = prefix + set[i]; // Next character of input added             
           printAllKLengthRec(set, newPrefix, n, k - 1,perms); // k is decreased, because we have added a new character 
        }
    }
	
}
