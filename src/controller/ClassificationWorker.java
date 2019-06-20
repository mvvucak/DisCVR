package controller;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.*;
import javax.swing.*;

import gui.DisCVRApplicationFrame;
import model.*;
import gui.ProgressPanel;
import gui.TablePanel;
import gui.TextPanel;


/***
 * A class to take input from the GUI, run sample classification, and then pass the results to the GUI 
 * for display.
 * 
 * @author Maha Maabar
 *
 */
public class ClassificationWorker extends SwingWorker <VirusResultDatabase, String> {
	
	public static final String DIR_PROPERTY_NAME = "discvrJAR.rootDir";
	public static final String currentDir = System.getProperty("user.dir");
	
	TreeMap<String,Integer> allMatchedKmers;
	VirusResultDatabase vrDB;
	SampleClassification sampleClass;
	String resultsText ;
	TextPanel textPanel;
	TextPanel summaryPanel;
	TablePanel tablePanel;
	ProgressPanel progressPanel; 
	JPanel scoring;
	DisCVRApplicationFrame appFrame;
	
	private String [] prams = new String [8];//Parameters passed from GUI
		
	public ClassificationWorker(final String prams [], final DisCVRApplicationFrame appFrame)  {
		vrDB = new VirusResultDatabase ();
		sampleClass = new SampleClassification();
		setResultsText("");
		this.prams = prams;
		this.textPanel = appFrame.getProgressText();
		this.summaryPanel = appFrame.getSummaryText();
		this.tablePanel = appFrame.getTablePanel();
		this.progressPanel = appFrame.getProgressPanel();
		this.scoring = appFrame.getScoring();
		this.appFrame = appFrame;
	}
	
	public ArrayList<VirusResult> getClassificationResult () {		
		return sampleClass.getVirusResultsList () ;		
	}
	
	public int getNumOfVirusResults () {
		return sampleClass.getResultSize();
	}
	
	public String getResultsText() {
		return resultsText;
	}
	
	//upload the classification results from a text into virusResultDatabase
	public void addResults (long num1, long num2){
		String [] line = getResultsText().split("\n");
		for (int i =0; i<line.length;i++){
			String [] virusInfo = line[i].split(": ");
			String name =virusInfo[0];
			String taxaID =virusInfo[1];
			int disKmersDB =Integer.parseInt(virusInfo[2]);
			int totKmersDB=Integer.parseInt(virusInfo[3]);
			int disKmers = Integer.parseInt(virusInfo[4]);
			int totKmers = Integer.parseInt(virusInfo[5]);
			String rank = virusInfo[6];
			VirusResult vResult = new VirusResult (name,taxaID,disKmers,totKmers,rank,disKmersDB,totKmersDB);
			vResult.setPercentage(disKmers, num1, 0); //First percentage is % of distinct k-mers
			vResult.setPercentage(totKmers, num2, 1); //Second percentage is % of total k-mers
			vrDB.addVirusResult(vResult);
		}		
	}
	
	public ArrayList<VirusResult> getResultDB () {
		ArrayList<VirusResult> resDB = null;
		// Changed method to make use of SwingWorker's in-built get() method for retrieving the results of doInBackground()
		try{
			return this.get().getVirusResults();
		}
		catch(final Exception e){
			e.printStackTrace();
		}

		return resDB;
		//return vrDB.getVirusResults();
	}
	
	//saves results of the classification to a file
	public void saveToFile (File file) throws IOException {
		vrDB.saveToFile(file);
	}
	
	//returns all the matched k-mers as an arrayList of the kmers and their counts 
	public ArrayList<Kmers> getAllMatchedKmers () {
		TreeMap<String,Integer> allMatchedKmers = sampleClass.getAllMatchedKmers();
		ArrayList<Kmers> kmersList = new ArrayList<Kmers>();
		//iterate over the treemap
		Set<Entry<String,Integer>> set = allMatchedKmers.entrySet(); //get a set of the entries
		Iterator<Entry<String,Integer>> i = set.iterator(); //get an iterator
		 
		 //Display elements
		 while (i.hasNext()) {
			 Map.Entry me =(Map.Entry)i.next();
			 
			 String kmerString = (String)me.getKey();
			 int count = (Integer) me.getValue();			 
			 Kmers akmer = new Kmers(kmerString,count);
			 
			 if(!kmersList.contains(akmer)) kmersList.add(akmer);			
		 }		
		return kmersList;
	}		
	
	public void setMatchedKmersMap() {
		allMatchedKmers =  sampleClass.getAllMatchedKmers();
	}
	
	/*
	 * Executes entire classification process:
	 * 	Sample KMer analysis using KAnalyze
	 * 	Database KMer reading and sorting into folders.
	 *  KMer matching between samples and database
	 *  Results summary and output to GUI.
	 *  Returns a VirusResultDatabase object if successful.
	 *  Return null if it encountered an error (such as a TimeOutException).
	 *  Both cases are handled by the done() method.
	 */
	protected  VirusResultDatabase doInBackground() throws Exception {		
		long startTime = System.currentTimeMillis();			
		String savingDir = prams [0]; 
		String sampleFile = prams [1];
		String kSize = prams [2];
		String inputFormat = prams [3];
		String kAnalyzeDir = prams [4];
		String dbLibrary = prams [5];
		String dbOption = prams [6];
		String entropyThrshld = prams [7];
		
		//Extracting the sample file name from the full path
		Path p = Paths.get(sampleFile);
		String file = p.getFileName().toString();
		int extIndex = file.indexOf('.');
		String filename = file.substring(0,extIndex);
				
		progressPanel.setValue(0); //0% on progress bar
		
		
		textPanel.appendText("\nExtracting Information from the Sample...\n");
		
		/*1st step: Counting k-mers from the sample file*/
		String sampleKmersFile = savingDir+"SampleKmers_"+kSize;
		String [] samplekmerCountingParms = {sampleFile, kSize,inputFormat, sampleKmersFile,kAnalyzeDir,entropyThrshld};

		// Count k-mers in sample using KAnalyze.
		// If this stage takes too long, an Error dialog pops up and the ClassificationWorker terminates.

		// Executor Service with its own thread to run KAnalyze.
		final ExecutorService kmerCountingService = Executors.newSingleThreadExecutor();
		// Variable to hold results once they are available (lambda function below can only use final variables)
		KmersCounting kC = null;

		final String[] finalSampleKmerCountingParms = samplekmerCountingParms.clone();
		try {
			final Future<KmersCounting> f = kmerCountingService.submit(() -> {
				final KmersCounting kmerCountResults = new KmersCounting(finalSampleKmerCountingParms);
				// Thread.sleep(80000); // Testing timeout function, remove.
				return kmerCountResults;
			});
			//If thread takes loner than 5 minutes to return result, throws TimeoutException
			kC = f.get(180, TimeUnit.MINUTES);
			sampleClass.setkC(kC);
		}
		catch(final TimeoutException e) {
			JOptionPane.showMessageDialog(null, "KAnalyze stage took too long",
					"Program Timeout", JOptionPane.ERROR_MESSAGE);
			deleteTempFolder(savingDir);
			return null;
		}
		catch (final Exception e)
		{
			throw new RuntimeException(e);
		}
		 
		String sampleInfo ="======================================================================\n";
		 sampleInfo =sampleInfo+"There are ("+String.format("%,d", kC.getNumOfReads())+") reads in the sample.\n"		 
		 +"There are ("+String.format("%,d", kC.getNumKmers())
		 +") distinct k-mers in the sample. The sum of their counts is ("+String.format("%,d",kC.getTotalKmersCounts())+")\n\n";
		
		 textPanel.appendText(sampleInfo);
		 
		 textPanel.appendText("Processing the sample k-mers...\n");
		             
		 sampleInfo ="======================================================================\n";
		 sampleInfo =sampleInfo+"Number of distinct k-mers removed, because they occur once in the sample, are ("+String.format("%,d", kC.getBadKmers())+")\n"
		 +"Number of distinct k-mers removed, due to their low complexity, are ("+String.format("%,d", kC.getLowEntropyKmers())+")\n\n"
		 +"Number of distinct k-mer in the sample to be classified are ("+String.format("%,d", kC.getGoodKmers())+")\n"
		 +"The sum of their counts is ("+String.format("%,d",kC.getTotalGoodKmers())+")\n\n";
		
		 textPanel.appendText(sampleInfo);
		 
		 /*2nd step: splitting files (sample k-mers and database k-mers) for matching */
		 final int permsPower = 5; //default setting for the permutations used to split large files
		 		 
         /* sample file splitting */
		 String statement = sampleClass.sampleFileSplitting (savingDir,sampleKmersFile, "s", kSize, permsPower);
		 		
		 publish("Finished splitting the sample Kmers file\n");//25% on progress bar
		 
        textPanel.appendText("Extracting information from the database...\n");

        /* Retrieval of database file */
        String databaseKmersFile = "";
        if (dbOption.equals("BuiltInDB")){
            databaseKmersFile= dbLibrary+"_"+kSize;
        }
        if(dbOption.equals("customisedDB")){
            databaseKmersFile=dbLibrary;
        }

		// Count and sort all k-mers in database into folder according to first 5 nucleotides.
		// If this stage takes too long, an Error dialog pops up and the ClassificationWorker terminates.

		// Executor Service with its own thread to run k-mer splitting.

        final ExecutorService databaseExtractionService = Executors.newSingleThreadExecutor();

        final String finalDatabaseKmersFile = databaseKmersFile;
        final String finalDbOption = dbOption;

        try {

            final Future<String> f = databaseExtractionService.submit(() -> {
                final String fileNamePrefix = savingDir+"db"+"Kmers_"; //prefix for all file names
                final String tempStatement = sampleClass.dbFileSplitting (finalDatabaseKmersFile, fileNamePrefix,
                        finalDbOption, "db",permsPower);
                return tempStatement;
            });
			//If thread takes loner than 1 minute to return result, throws TimeoutException
            statement = f.get(30, TimeUnit.MINUTES);
            sampleClass.setkC(kC);
        }
        catch(final TimeoutException e) {
			JOptionPane.showMessageDialog(null, "Database kmer splitting took too long.",
					"Program Timeout", JOptionPane.ERROR_MESSAGE);
			deleteTempFolder(savingDir);
			return null;
        }
        catch (final Exception e)
        {
        	System.err.println("Here");
            throw new RuntimeException(e);
        }



		 publish("Finished Splitting the database Kmers file\n");//50% on progress bar	 
		 
		 textPanel.appendText(statement);

		
		/* 3rd step: matching sample k-mers to database k-mers*/
		textPanel.appendText("matching Sample k-mers with the Database k-mers...\n");

        final ExecutorService kmerMatchingService = Executors.newSingleThreadExecutor();
        int[] numOfMatches = {0,0};

		// Match all k-mers in sample to k-mers in database
		// If this stage takes too long, an Error dialog pops up and the ClassificationWorker terminates.

		// Executor Service with its own thread to run k-mer matching.

        try {
            final Future<int[]> f = kmerMatchingService.submit(() -> {
                final SampleKmersMatching fsKM = new SampleKmersMatching();
                sampleClass.setKM(fsKM);
                final int[] fNumOfMatches = fsKM.searchForKmersMatches(savingDir, Integer.parseInt(kSize), permsPower,filename);
                return fNumOfMatches;
            });
			//If thread takes loner than 1 minute to return result, throws TimeoutException
            numOfMatches = f.get(60, TimeUnit.MINUTES);
        }
        catch(final TimeoutException e){
			JOptionPane.showMessageDialog(null, "Kmer matching took too long.",
					"Program Timeout", JOptionPane.ERROR_MESSAGE);
			deleteTempFolder(savingDir);
			return null;
        }
        catch(final Exception e)
        {
            throw new RuntimeException(e);
        }

		 		 
		statement="======================================================================\n";
		statement=statement+"There are ("+String.format("%,d",numOfMatches[0])+") distinct k-mers in the sample matched with the database.\n";
		statement=statement+"The total number of their counts is ("+String.format("%,d",numOfMatches[1])+")\n";
		  	
		 textPanel.appendText(statement);
		 
		 publish("Finished matching Sample K-mers with the Database K-mers.\n");//*75% on progress bar
		
		 /*4th step: printing matching results*/
		 String matchFileName = savingDir+"allMatchedKmers_"+filename+"_"+kSize;

		// Analyse and summarize results in bar charts and tables.
		// If this stage takes too long, an Error dialog pops up and the ClassificationWorker terminates.

		// Executor Service with its own thread to run results analysis and table/figure creation.

        final ExecutorService summaryService = Executors.newSingleThreadExecutor();
        String timeText = "";

        try
        {
            ResultsSummarizer resultsSummarizer = new ResultsSummarizer(getResultsText(), sampleClass, matchFileName,
                    databaseKmersFile, dbOption, numOfMatches, textPanel, summaryPanel, this, scoring, vrDB,
					kC, startTime);
            final Future<String> f = summaryService.submit(resultsSummarizer);
            timeText = f.get(30, TimeUnit.MINUTES);
        }
		//If thread takes loner than 1 minute to return result, throws TimeoutException
        catch(final TimeoutException e){
			JOptionPane.showMessageDialog(null, "Result summary stage took too long.",
					"Program Timeout", JOptionPane.ERROR_MESSAGE);
			deleteTempFolder(savingDir);
			return null;
        }
        catch(final Exception e)
        {
        	e.printStackTrace();
        }

        textPanel.appendText("\nTime taken (hh:mm:ss): "+timeText);

        publish("Done!\n\n"); //100% on progress bar
				 
		deleteTempFolder(savingDir);//delete temp files
		return vrDB;
	}
	
	/*
	 * Updates progress bar by passing an array of strings.
	 * Progress is incremented by 25% for each string in the array (see Progress Panel setValue()
	 */
	protected void process(final List<String> chunks) {
		int value = progressPanel.getValue();		
	    // Updates the messages text area
	    for (final String str : chunks) {	    	
	        value++;
	        progressPanel.setValue(value);
	     }
	 }
	
	//uploads results on the table when classification is done
	protected void done(){
		try{
			if (this.get() == null){
				//Do Nothing?
				System.err.println("Resetting everything");
				appFrame.resetAllFields();
			}
			else {
				tablePanel.setData(getResultDB());
				tablePanel.refresh();
				appFrame.enableClassifyButton();
			}
		}
		catch(final Exception e){
			e.printStackTrace();
		}


	}
	
	private  void deleteTempFolder(String dirName)   {
		final File dir = new File(dirName);
	    final String[] allFiles = dir.list();   
        for (int i=0; i<allFiles.length; i++) {
               File aFile = new File(dir,allFiles[i]); 
               aFile.delete();
        }
      dir.delete();
	}

	public void setResultsText(String resultsText) {
		this.resultsText = resultsText;
	}
}
