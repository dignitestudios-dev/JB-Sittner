import { useState, useEffect, useContext } from "react";
import {
  format,
  subMonths,
  addMonths,
  subYears,
  addYears,
  isEqual,
  getDaysInMonth,
  getDay,
} from "date-fns";
import { FaChevronRight } from "react-icons/fa6";
import { MyContext } from "../../context/GlobalContext";

const DatepickerType = "date" | "month" | "year";

export default function DatePicker(props) {
  const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
  const [dayCount, setDayCount] = useState([]);
  const { setSelectDate } = useContext(MyContext);
  const [blankDays, setBlankDays] = useState([]);
  const [showDatepicker, setShowDatepicker] = useState(false);
  const [datepickerHeaderDate, setDatepickerHeaderDate] = useState(new Date());

  const [selectedDate, setSelectedDate] = useState(new Date());
  useEffect(() => {
    if (props.date) {
      const parsedDate = new Date(props.date);
      if (!isNaN(parsedDate)) {
        console.log("Updating selectedDate to:", parsedDate);
        setSelectedDate(parsedDate);
        setSelectDate(parsedDate.toLocaleDateString());
      }
    }
  }, [props.date]);

  const [type, setType] = useState("date");

  const decrement = () => {
    switch (type) {
      case "date":
        setDatepickerHeaderDate((prev) => subMonths(prev, 1));
        break;
      case "month":
        setDatepickerHeaderDate((prev) => subYears(prev, 1));
        break;
      case "year":
        setDatepickerHeaderDate((prev) => subMonths(prev, 1));
        break;
    }
  };

  const increment = () => {
    switch (type) {
      case "date":
        setDatepickerHeaderDate((prev) => addMonths(prev, 1));
        break;
      case "month":
        setDatepickerHeaderDate((prev) => addYears(prev, 1));
        break;
      case "year":
        setDatepickerHeaderDate((prev) => subMonths(prev, 1));
        break;
    }
  };

  const isToday = (date) =>
    isEqual(
      new Date(selectedDate.getFullYear(), selectedDate.getMonth(), date),
      selectedDate
    );

  // const setDateValue = (date) => () => {
  //   console.log(date);
  //   setSelectedDate(
  //     new Date(
  //       datepickerHeaderDate.getFullYear(),
  //       datepickerHeaderDate.getMonth(),
  //       date
  //     )
  //   );

  //   setSelectDate(
  //     new Date(
  //       datepickerHeaderDate.getFullYear(),
  //       datepickerHeaderDate.getMonth(),
  //       date
  //     ).toLocaleDateString()
  //   );
  //   setShowDatepicker(false);
  // };

  const setDateValue = (date) => () => {
    console.log(date);

    // Create the new Date object for the selected date
    const selectedDate = new Date(
      datepickerHeaderDate.getFullYear(),
      datepickerHeaderDate.getMonth(),
      date
    );

    // Format the selected date using Intl.DateTimeFormat
    const formattedDate = new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(selectedDate);

    // Set the selected date and formatted date
    setSelectedDate(selectedDate);
    setSelectDate(formattedDate); // Store the formatted date string

    // Close the date picker
    setShowDatepicker(false);
  };

  const getDayCount = (date) => {
    let daysInMonth = getDaysInMonth(date);
    let dayOfWeek = getDay(new Date(date.getFullYear(), date.getMonth(), 1));

    // Adjust the calculation to align Sundays properly
    let blankdaysArray = Array.from(
      { length: dayOfWeek === 0 ? 6 : dayOfWeek - 1 },
      (_, i) => i + 1
    );
    let daysArray = Array.from({ length: daysInMonth }, (_, i) => i + 1);

    setBlankDays(blankdaysArray);
    setDayCount(daysArray);
  };

  const isSelectedMonth = (month) =>
    isEqual(
      new Date(selectedDate.getFullYear(), month, selectedDate.getDate()),
      selectedDate
    );

  const setMonthValue = (month) => () => {
    setDatepickerHeaderDate(
      new Date(
        datepickerHeaderDate.getFullYear(),
        month,
        datepickerHeaderDate.getDate()
      )
    );
    setType("date");
  };

  const toggleDatepicker = () => setShowDatepicker((prev) => !prev);

  const showMonthPicker = () => setType("month");

  const showYearPicker = () => setType("date");

  useEffect(() => {
    getDayCount(datepickerHeaderDate);
  }, [datepickerHeaderDate]);

  return (
    <div>
      <div className="w-full lg:w-64">
        <div className="relative">
          <input type="hidden" name="date" />
          <input
            type="text"
            readOnly
            className="cursor-pointer w-full pl-10 pr-10  leading-none bg-white border border-color text-gray-900 text-sm rounded-[12px]  mt-1  block h-[40px] focus:outline-[#0A8A33]"
            placeholder="Select date"
            value={format(selectedDate, "yyyy-MM-dd")}
            onClick={toggleDatepicker}
          />
          <div
            className="cursor-pointer absolute top-0 left-0 px-3 py-2"
            onClick={toggleDatepicker}
          >
            <img src="/agenda.png" className="w-5" alt="" srcset="" />
          </div>
          {showDatepicker && (
            <div
              className="bg-white mt-12 rounded-lg shadow p-4 absolute top-0 left-0"
              style={{ width: "17rem", zIndex: "99999999" }}
            >
              <div className="flex items-center mb-2">
                {type === "date" && (
                  <div
                    onClick={showMonthPicker}
                    className=" flex items-center text-[20px] gap-2 font-bold"
                  >
                    <div className="text-center">
                      {format(datepickerHeaderDate, "MMMM")}{" "}
                      {format(datepickerHeaderDate, "yyyy")}
                    </div>
                    <div>
                      <button
                        type="button"
                        className="mt-2"
                        onClick={increment}
                      >
                        <FaChevronRight />
                      </button>
                    </div>
                  </div>
                )}
              </div>
              {type === "date" && (
                <>
                  <div className="flex flex-wrap mb-3 -mx-1">
                    {DAYS.map((day, i) => (
                      <div key={i} style={{ width: "14.26%" }} className="px-1">
                        <div className="text-gray-800 font-normal text-[#3C3C4399] text-center text-[12px]">
                          {day}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="flex flex-wrap -mx-1">
                    {blankDays.map((_, i) => (
                      <div
                        key={i}
                        style={{ width: "14.26%" }}
                        className="text-center border p-1 border-transparent text-sm"
                      ></div>
                    ))}
                    {dayCount.map((d, i) => {
                      const dateToCheck = new Date(
                        datepickerHeaderDate.getFullYear(),
                        datepickerHeaderDate.getMonth(),
                        d
                      );

                      // Get the current date without time
                      const today = new Date();
                      today.setHours(0, 0, 0, 0); // Reset time to midnight

                      const isPastDate = dateToCheck < today;

                      return (
                        <div
                          key={i}
                          style={{ width: "14.26%" }}
                          className="px-1 mb-2"
                        >
                          <button
                            disabled={isPastDate}
                            onClick={setDateValue(d)}
                            className={`cursor-pointer text-center text-sm leading-none rounded-full leading-loose transition ease-in-out duration-100 
          ${isToday(d) ? "text-[#0A8A33]" : "hover:text-[#0A8A33]"} 
          ${getDay(dateToCheck) === 0 ? "text-red-500" : ""} 
          ${isPastDate ? "opacity-50 cursor-not-allowed" : ""}
        `}
                          >
                            {d}
                          </button>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
              {type === "month" && (
                <div className="flex flex-wrap -mx-1">
                  {Array(12)
                    .fill(null)
                    .map((_, i) => (
                      <div
                        key={i}
                        onClick={setMonthValue(i)}
                        style={{ width: "25%" }}
                      >
                        <div
                          className={`cursor-pointer p-5 font-semibold text-center text-sm rounded-lg hover:bg-gray-200 ${
                            isSelectedMonth(i)
                              ? "bg-blue-500 text-white"
                              : "text-gray-700 hover:bg-blue-200"
                          }`}
                        >
                          {format(
                            new Date(
                              datepickerHeaderDate.getFullYear(),
                              i,
                              datepickerHeaderDate.getDate()
                            ),
                            "MMM"
                          )}
                        </div>
                      </div>
                    ))}
                </div>
              )}{" "}
              {type === "year" && (
                <Datepicker
                  datepickerHeaderDate={datepickerHeaderDate}
                  selectedDate={selectedDate}
                  setSelectedDate={setSelectedDate}
                  closeDatepicker={() => setShowDatepicker(false)}
                />
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
