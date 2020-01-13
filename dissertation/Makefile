# This is the Makefile for the demonstration dissertation
# written by Martin Richards
#
# Note that continuation lines require '\'
# and that TAB is used after ':' and before unix commands.

DISS = diss.tex refs.bib 

diss.pdf: $(DISS)	
	xelatex -interaction=nonstopmode diss.tex
	biber diss
	xelatex -interaction=nonstopmode diss.tex

count:
	detex diss.tex | tr -cd '0-9A-Za-z \n' | wc -w

clean:
	rm -f diss.ps *.dvi *.aux *.log *.err
	rm -f core *~ *.lof *.toc *.blg *.bbl
