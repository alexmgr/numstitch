#!/usr/bin/env python
# -*- coding:utf-8 -*-

def solve_dp(coins, change):
	"""Coin change problem solver using dynamic programming
	Refer to wikipedia for the description: http://en.wikipedia.org/wiki/Coin_problem
	And to this blog for a nice explanation: http://interactivepython.org/runestone/static/pythonds/Recursion/recursioncomplex.html
	And here fo a half working implementation: http://bryceboe.com/2009/11/04/dynamic-programming-%E2%80%93-coin-change-problem-in-python/
	"""
	table = [None for x in xrange(change + 1)]
	table[0] = []
	for i in xrange(1, change + 1):
		for coin in coins:
			length = 0
			if table[i - coin] != None:
				length = len(table[i - coin])
			if coin > i: continue
			elif not table[i] or (length + 1 < len(table[i])):
				if table[i - coin] != None:
					table[i] = table[i - coin][:]
					table[i].append(coin)
	return len(table[-1]) if table[-1] != None else 0, table[-1] if table[-1] != None else None

def solve_gready(coins, change):
	biggest_first = reversed(sorted(coins))
	accumulator = change
	solution = []
	for number in biggest_first:
		if number <= accumulator:
			solution.append(number)
			accumulator -= number
		if accumulator == 0:
			break
	if accumulator != 0:
		solution = None
	return len(solution) if solution != None else 0, solution
