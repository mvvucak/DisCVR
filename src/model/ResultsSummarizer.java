package model;

import controller.ClassificationWorker;
import gui.ScoringPanel;
import gui.TextPanel;

import javax.swing.*;
import java.awt.*;
import java.util.concurrent.Callable;

/*
 * Callable class called by an ExecutorService thread in ClassificationWorker to summarize kmer matching results
 * and create graphs and tables to display in the JPanel.
 * This is an inelegant solution that circumvents the problem of having to use final variables in a lambda expression
 * (which is how the other 3 ExecutorService threads in ClassificationWorker are run). The original implementation made
 * the use of final variables impossible.
 */

public class ResultsSummarizer implements Callable<String> {

    // We must pass ALL the variables used in that section of ClassificationWorker's doInBackground method.
    private String resultsText;
    private SampleClassification sampleClass;
    private String matchFileName;
    private String databaseKmersFile;
    private String dbOption;
    private int[] numOfMatches;
    private TextPanel textPanel;
    private TextPanel summaryPanel;
    private ClassificationWorker cw;
    private JPanel scoring;
    private VirusResultDatabase vrDB;
    private KmersCounting kC;
    private long startTime;

    public ResultsSummarizer(String resultsText, SampleClassification sampleClass, String matchFileName, String databaseKmersFile,
                             String dbOption, int[] numOfMatches, TextPanel textPanel, TextPanel summaryPanel,
                             ClassificationWorker cw, JPanel scoring, VirusResultDatabase vrDB, KmersCounting kC,
                             long startTime){

        this.resultsText = resultsText;
        this.sampleClass = sampleClass;
        this.matchFileName = matchFileName;
        this.databaseKmersFile = databaseKmersFile;
        this.dbOption = dbOption;
        this.numOfMatches = numOfMatches;
        this.textPanel = textPanel;
        this.summaryPanel = summaryPanel;
        this.cw = cw;
        this.scoring = scoring;
        this.vrDB = vrDB;
        this.kC = kC;
        this.startTime = startTime;
    }

    public String call(){
        // Update resultsText in ClassificationWorker using setter.
        resultsText = sampleClass.printingMatchingResults(matchFileName,databaseKmersFile,dbOption);
        cw.setResultsText(resultsText);

        if(numOfMatches[0]==0){ //zero matches

            textPanel.appendText("\n\nRESULTS...\n"
                    +"======================================================================\n"
                    +"There are  "+String.format("%,d",numOfMatches[0])+"  viruses found in the sample.");
        }
        else {

            String summaryText =sampleClass.getSummaryText();
            summaryPanel.appendText(summaryText);

            String [] highestScoresNames = sampleClass.getHighestScoresVirus();
            int [] highestScoresResults = sampleClass.getHighestScoresSpecific();
            int [] highestScoresShared = sampleClass.getHighestScoresShared();

            //add the top scores to the scoring panel
            scoring.setLayout(new BorderLayout());
            scoring.add(new ScoringPanel(highestScoresNames,highestScoresResults,highestScoresShared), BorderLayout.WEST);


            cw.addResults(kC.getGoodKmers(),kC.getTotalGoodKmers());

            textPanel.appendText("\n\nRESULTS...\n"
                    +"======================================================================\n"
                    +"There are  "+String.format("%,d",vrDB.getDBSize())+"  virus(es) found in the sample.");
        }
        final long endTime = System.currentTimeMillis();
        final long time=endTime-startTime;

        /*calculate run classification time*/
        final int seconds = (int)(time / 1000) % 60 ;
        final int minutes = (int)((time / (1000*60)) % 60);
        final int hours = (int)((time / (1000*60*60)) % 24);

        final String finalTimeText = String.format("%02d:%02d:%02d", hours, minutes, seconds);
        return finalTimeText;
    }
}
