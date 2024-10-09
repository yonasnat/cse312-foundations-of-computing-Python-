"""
This solution code is written by Alex Tsun and modified by Pemi Nguyen.
Permission is hereby granted to students registered for the  University
of Washington CSE 312 for use solely during Winter Quarter 2024 for purposes
of the course.  No other use, copying, distribution, or modification is
permitted without prior written consent.
"""

# =============================================================
# You may define helper functions, but DO NOT MODIFY
# the parameters or names of the provided functions.
# The autograder will expect that these functions exist
# and attempt to call them to grade you.

# Do NOT add any import statements.
# =============================================================

import numpy as np
from typing import List, Set, Dict
import os

# ===================== ABOUT THE DATA ========================
# Inside the 'data' folder, the emails are separated into 'train' 
# and 'test' data. Each of these folders has nested 'spam' and 'ham'
# folders, each of which has a collection of emails as txt files.
# You will only use the emails in the 'train' folder to train your 
# classifier, and will evaluate on the 'test' folder.
        
# The emails we are using are a subset of the Enron Corpus,
# which is a set of real emails from employees at an energy
# company. The emails have a subject line and a body, both of
# which are 'tokenized' so that each unique word or bit of
# punctuation is separated by a space or newline. The starter
# code provides a function that takes a filename and returns a
# set of all of the distinct tokens in the file.
# =============================================================

class NaiveBayes():
    """
    This is a Naive Bayes spam filter, that learns word spam probabilities 
    from our pre-labeled training data and then predicts the label (ham or spam) 
    of a set of emails that it hasn't seen before. See the handout from section 2
    for details on implementation!
    """
    def __init__(self):
        """
        These variables are described in the 'fit' function below. 
        You will also need to access them in the 'predict' function.
        """
        self.num_train_hams = 0
        self.num_train_spams = 0
        self.word_counts_spam = {}
        self.word_counts_ham = {}
        self.HAM_LABEL = 'ham'
        self.SPAM_LABEL = 'spam'

    def load_data(self, path:str='data/'):
        """
        This function loads all the training and test data and returns
        the filenames as lists. You do not need to worry about how this
        function works unless you're curious.

        :param path: Expects a path such that inside are two folders:
        'train' and 'test'. Each of these two folders should have a 'spam' and
        'ham' folder inside. These four folders now all should just contain
        several txt files.
        :return: Inside a tuple, 
            1. A list with the ham training data filenames.
            2. A list with the spam training data filenames.
            3. A list with the ham test data filenames.
            4. A list with the spam test data filenames.
        """
        assert set(os.listdir(path)) == set(['test', 'train'])
        assert set(os.listdir(os.path.join(path, 'test'))) == set(['ham', 'spam'])
        assert set(os.listdir(os.path.join(path, 'train'))) == set(['ham', 'spam'])

        train_hams, train_spams, test_hams, test_spams = [], [], [], []
        for filename in os.listdir(os.path.join(path, 'train', 'ham')):
            train_hams.append(os.path.join(path, 'train', 'ham', filename))
        for filename in os.listdir(os.path.join(path, 'train', 'spam')):
            train_spams.append(os.path.join(path, 'train', 'spam', filename))
        for filename in os.listdir(os.path.join(path, 'test', 'ham')):
            test_hams.append(os.path.join(path, 'test', 'ham', filename))
        for filename in os.listdir(os.path.join(path, 'test', 'spam')):
            test_spams.append(os.path.join(path, 'test', 'spam', filename))

        return train_hams, train_spams, test_hams, test_spams

    def word_set(self, filename:str) -> Set[str]:
        """ 
        This function reads in a file and returns a set of all 
        the words. It ignores the subject line.

        :param path: The filename of the email to process.
        :return: A set of all the unique word in that file.

        For example, if the email had the following content:

        -------------------------------------------
        Subject: Get rid of your student loans
        Hi there,
        If you work for us, we will give you money
        to repay your student loans. You will be
        debt free!
        FakePerson_22393
        -------------------------------------------

        This function will return to you the set:
        {'', 'work', 'give', 'money', 'rid', 'your', 'there,',
            'for', 'Get', 'to', 'Hi', 'you', 'be', 'we', 'student',
            'debt', 'loans', 'loans.', 'of', 'us,', 'will', 'repay',
            'FakePerson_22393', 'free!', 'You', 'If'}
        """
        with open(filename, 'r') as f:
            text = f.read()[9:] # Ignoring 'Subject:'
            text = text.replace('\r', '')
            text = text.replace('\n', ' ')
            words = text.split(' ')
            return set(words)

    def fit(self, train_hams:List[str], train_spams:List[str]):
        """
        This function is a part of the training process, where you gather
        information from the training set. Specifically, here you are calculating
        the number of spam and ham emails in the training set and the frequency of
        each word in the train ham and spam emails.

        :param train_hams: A list of training email filenames which are ham.
        :param train_spams: A list of training email filenames which are spam.
        :return: Nothing.

        At the end of this function, the following should be true:
        1. self.num_train_hams is set to the number of ham emails given.
        2. self.num_train_spams is set to the number of spam emails given.
        3. self.word_counts_spam is a dictionary which stores the frequency of each word
        that appears in the training spam emails
        4. self.word_counts_ham is a dictionary which stores the frequency of each word
        that appears in the training ham emails

        Hint: You may want to use the self.word_set function provided.

        Note: Please don't apply Laplace smoothing or anything here,
        simply make sure your counts are correct from the raw data you're given.
        """
        for ham_file in train_hams:                 
            ham_info = self.word_set(ham_file)       
            for ham_word in ham_info:                    
                if ham_word in self.word_counts_ham:            
                    self.word_counts_ham[ham_word] += 1             
                else:
                    self.word_counts_ham[ham_word] = 1          
        self.num_train_hams = len(train_hams)           

        for spam_file in train_spams:               
            spam_info = self.word_set(spam_file)       
            for spam_word in spam_info:                    
                if spam_word in self.word_counts_spam:            
                    self.word_counts_spam[spam_word] += 1            
                else:
                    self.word_counts_spam[spam_word] = 1          
        self.num_train_spams = len(train_spams)          

        def get_counts(filenames:List[str]) -> Dict[str, int]:
            """
            This is an OPTIONAL nested function only accessible by parent 'fit',
            which we're in now. You may want to implement this function
            to avoid writing the same code for self.word_counts_spam and
            self.word_counts_ham!
            :param filenames: a list of email filenames
            :return: A dictionary which stores the frequency of each word that appears
            in all emails in that list.
            """
            pass

        pass # TODO: Your code here (~10-20 lines)
        
    def predict(self, filename:str) -> str:
        """
        This function returns the prediction for each email (spam or ham).
        :param filename: The filename of an email to classify.
        :return: The prediction of our Naive Bayes classifier. This
        should either return self.HAM_LABEL or self.SPAM_LABEL.

        Guidelines:
        1. Make sure to use the log-trick to avoid underflow.
        2. Make sure for Laplace smoothing you use +1 in numerator 
        and +2 in denominator. This is even for words you haven't seen before
        in the training data, which would otherwise have 0 probability.
        3. Do not 'cheat' - meaning looking up the true label. We will
        test your code on a dataset you don't have access to. Remember,
        the goal is not 100% accuracy - a correct implementation will get
        exactly a certain accuracy.
        4. In case of a tie, predict 'self.HAM_LABEL'.
        5. Do NOT apply Laplace smoothing to P(ham) and P(spam).

        Hint(s):
        1. You may want to use the self.word_set function provided.
        2. Use np.log(...) to take logs.
        3. For a dictionary d, d[key] returns the value if the key exists.
        But if it doesn't, you get an error. To simplify your code,
        d.get(key, 0) will return d[key] if it exists, otherwise 0. 
        4. You'll want to use the values you set during the fit function.
        Access those variables with a 'self' prefix, like self.num_train_hams.
        """
        pass # TODO: Your code here (~10-20 lines)

        total_emails = self.num_train_hams + self.num_train_spams                     # all emails total
        prob_ham = np.log(self.num_train_hams/total_emails)                    # probability of ham 
        prob_spam = np.log(self.num_train_spams/total_emails)                  # probability of spam
        
        email_content_set = self.word_set(filename)                                   
        for email_word in email_content_set:                                                
            ham_word_count = self.word_counts_ham.get(email_word,0)                        
            prob_ham_word = (ham_word_count + 1)/(self.num_train_hams + 2)    
            prob_ham += np.log(prob_ham_word)                           
            
            spam_word_count = self.word_counts_spam.get(email_word,0)                      
            prob_spam_word = (spam_word_count + 1)/(self.num_train_spams + 2) 
            prob_spam += np.log(prob_spam_word)                         
        
        if prob_ham >= prob_spam:
            return self.HAM_LABEL
        else:
            return self.SPAM_LABEL
    
    def accuracy(self, hams:List[str], spams:List[str]) -> float:
        """
        This function returns the accuracy of our Naive Bayes model.

        :param hams: A list of email filenames which are hams.
        :param spams: A list of email filenames which are spams.
        :return: The proportion of correctly classified spam and ham emails
        in a certain list of emails.

        Note: This function returns the training accuracy if
        parameters hams and spams are training emails. If they are test emails,
        it returns the test accuracy.
        """
        all_correct = 0
        all_datapoints = len(hams) + len(spams)
        for ham_filename in hams:
            if self.predict(ham_filename) == self.HAM_LABEL:
                all_correct += 1
        for spam_filename in spams:
            if self.predict(spam_filename) == self.SPAM_LABEL:
                all_correct += 1
        return all_correct / all_datapoints

if __name__ == '__main__':
    # Create a Naive Bayes classifier.
    nbc = NaiveBayes()

    # Load all the training/test ham/spam data.
    train_hams, train_spams, test_hams, test_spams = nbc.load_data()

    # Fit the model to the training data.
    nbc.fit(train_hams, train_spams)

    # Print out the accuracy on the training and test sets.
    print("Training Accuracy: {}".format(nbc.accuracy(train_hams, train_spams)))
    print("Test  Accuracy: {}".format(nbc.accuracy(test_hams, test_spams)))
