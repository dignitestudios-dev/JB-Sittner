import React, { useContext, useEffect, useState } from "react";
import { TimePicker } from "react-ios-time-picker";
import { MyContext } from "../../context/GlobalContext";

export const ModernTimePicker = ({time}) => {
  const {setSelectTime}=useContext(MyContext);
  const [value, setValue] = useState(time || '10:00 AM'); 
  useEffect(() => {
    if (time) {
      console.log("Updating value to:", time);
      setValue(time);
      setSelectTime(time)
    }
  }, [time]);

  const onChange = (timeValue) => {
    setValue(timeValue);
    setSelectTime(timeValue);
  };


  return (
    <div className="relative mt-3 lg:mt-0">
      <TimePicker 
        key={value}
        onChange={onChange} 
        value={value} 
        use12Hours 
      />
      <img
        src="/clock.png"
        alt=""
        className="absolute  bottom-[23%] ml-2 w-5"
        srcset=""
      />
    </div>
  );
};
