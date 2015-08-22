# Holiday Calculator

Sometimes you just need to know when the next holiday is. Incredeiably useful for any app that requires scheduling, date selection or anything to do with timing.

Code originally published http://www.codecutout.com/holiday-calculator and is still a good description

## Installation

No nuget package, seems a bit wasteful since it is only a single file. 

Just copy the file `DateCalculator.cs` into your project


## Configuration

Holidays are dependant on location and will require configuration, there is no way around it so you need to configure which holidays you care about. Below is a sample configuration for Auckland, New Zealand. Although some dates are Auckland specific the format is fleixable enough for it to be edited to fit any set of dates you need with whatever festive days you want to celebrate 

``` XML
<?xml version="1.0" encoding="utf-8" ?>
<configuration>
	<configSections>
		<section name="HolidaySet" type="MyNameSpace.HolidaySet, MyAssembly"/>
	</configSections>

	<HolidaySet>
		<Holiday Name="New Years Day">
			<WeekdayOnOrAfter>
				<FixedDate Day="1" Month="1" />
			</WeekdayOnOrAfter>
		</Holiday>

		<Holiday Name="Day after New Years Day">
			<WeekdayOnOrAfter>
				<DaysAfter Days="1">
					<WeekdayOnOrAfter>
						<FixedDate Day="1" Month="1" />
					</WeekdayOnOrAfter>
				</DaysAfter>
			</WeekdayOnOrAfter>
		</Holiday>

		<Holiday Name="Auckland Anniversary">
			<ClosestDayOfWeek DayOfWeek="Monday">
				<FixedDate Day="29" Month="1" />
			</ClosestDayOfWeek>
		</Holiday>

		<Holiday Name="Waitangi Day">
			<FixedDate Day="6" Month="2" />
		</Holiday>

		<Holiday Name="Good Friday">
			<DaysAfter Days="-2">
				<EasterSunday />
			</DaysAfter>
		</Holiday>

		<Holiday Name="Easter Monday">
			<DaysAfter Days="1">
				<EasterSunday />
			</DaysAfter>
		</Holiday>

		<Holiday Name="ANZAC Anniversary">
			<FixedDate Day="25" Month="4" />
		</Holiday>

		<Holiday Name="Queens Birthday">
			<XthDayOfWeekInMonth DayOfWeek="Monday" DayOccurance="1" Month="6" />
		</Holiday>

		<Holiday Name="Labour Day">
			<XthDayOfWeekInMonth DayOfWeek="Monday" DayOccurance="4" Month="10" />
		</Holiday>

		<Holiday Name="Christmas Day">
			<WeekdayOnOrAfter>
				<FixedDate Day="25" Month="12" />
			</WeekdayOnOrAfter>
		</Holiday>

		<Holiday Name="Boxing Day">
			<WeekdayOnOrAfter>
				<DaysAfter Days="1">
					<WeekdayOnOrAfter>
						<FixedDate Day="25" Month="12" />
					</WeekdayOnOrAfter>
				</DaysAfter>
			</WeekdayOnOrAfter>
		</Holiday>

	</HolidaySet>

</configuration>

```

The configuration is made up of nesting elements. The out of the box elements are 
 * FixedDate - to get a date like e.g. 19th of February
 * WeekdayOnOrAfter - to force a holiday to fall on a weekday, if it would normally fall on a weekend. e.g. 25th december, but if it falls on a weekend it will be the next Monday
 * DaysAfter - to allow a holiday to occur some days after (or before) another date e.g. Easter Monday is 1 day after easter sunday
 * XthDayOfWeekInMonth - to get dates in a specific week of hte month e.g. the second Wednesday in July
 * ClosestDayOfWeek - to allow you to get the closest day to a given date. e.g. The closest monday to the 29th of January.
 * EasterSunday - because it is a common holiday but is hard to calculate

## Usage in code
```C#

//read our configuration file to get our holiday set
var holidaySet = (HolidaySet)ConfigurationManager.GetSection("HolidaySet");

//return all the holiday dates between two dates
IEnumerable<DateTime> nextYearsHolidays = holidaySet.GetHolidays(DateTime.Now, DateTime.Now.AddYears(1));

//determine if a given date is a holiday
bool isItAHolidayToday = holidaySet.IsHoliday(DateTime.Now);

```

## Extension

If you cant build the dates you want out of the built-in elements you can create your own elements by extending DateCalculator

```C#

public class DaysAfter : DateCalculator
{
	//Any property will be read from the attributes
	public int Days { get; set; }

	//A DateCalculator property will be read from teh inner attribute
	public DateCalculator Inner { get; set; }

	//Method should return the next occurance of hte holiday that is on or after the given start date
	//if the method returns null it is implying this holiday will never happen again
	public override DateTime? NextDate(DateTime startDate)
	{
		foreach (var innerDate in Inner.NextDates(startDate.AddDays(-Days)))
		{
			var nextDate = innerDate.AddDays(Days);
			if (nextDate > startDate)
				return nextDate;
		}
		return null;
	}
}

```