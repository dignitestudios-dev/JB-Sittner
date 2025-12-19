import React, { useContext, useEffect, useState } from "react";
import { FaChevronUp } from "react-icons/fa";
import { FaAngleDown } from "react-icons/fa6";
import { NavLink } from "react-router-dom";
import { MyContext } from "../../context/GlobalContext";
import { collection, db, onSnapshot, query } from "../../firbase/FirebaseInit";
export default function Member() {
  const [openIndex, setOpenIndex] = useState(null);
  const { LookScreen, setIsAddMem, AddMem } = useContext(MyContext);
  const handleToggle = (index) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  const user = [
    {
      title: "Adam Gilchrist",
      img: "/large-person-4.png",
    },
    {
      title: "Mike Tyson",
      img: "/large-person-3.png",
    },
    {
      title: "Andrew Garfield",
      img: "/large-person-2.png",
    },
    {
      title: "John Cena",
      img: "/large-person-1.png",
    },
  ];

  const color = [
    "bg-[#B9FF9E]",
    "bg-[#FFD839]",
    "bg-[#E8F569]",
    "bg-[#94D0E4]",
  ];

  const [employee, setEmployee] = useState([]);
  const getEmploye = () => {
    const employeesRef = collection(db, "employee");
    const employeeQuery = query(employeesRef);
    const unsubscribe = onSnapshot(employeeQuery, (querySnapshot) => {
      const employeeData = querySnapshot.docs.map((doc) => ({
        docid: doc.id,
        ...doc.data(),
      }));
      setEmployee(employeeData);
    });
    return unsubscribe;
  };

  useEffect(() => {
    const unsubscribe = getEmploye();
    return () => unsubscribe();
  }, []);


  return (
    <div>
      <div
        id="accordion-collapse"
        data-accordion="collapse"
        className={`${LookScreen ? "w-[40%]" : "w-full"}   mt-2 mx-auto`}
      >
        <div
          type="button"
          className={`flex flex-col items-start justify-between w-full py-4 font-medium rtl:text-right outline-none hover:opacity-95 `}
          data-accordion-target="#accordion-collapse-body-1"
        >
          <button
            name="faq-question"
            type="button"
            className={`flex my-divider pb-2  items-center justify-between w-full  font-medium rtl:text-right  outline-none hover:opacity-95  gap-3`}
            onClick={() => !LookScreen && handleToggle(1)}
          >
            <div
              className={`w-auto flex justify-start items-center text-xs md:text-sm lg:text-xl text-left gap-2 `}
            >
              <h2 className={`font-medium text-[13px]`}>Members</h2>
            </div>
            {!LookScreen &&
              (openIndex === 1 ? (
                <FaAngleDown className="text-xl" />
              ) : (
                <FaChevronUp className="text-xl" />
              ))}
          </button>
          <div
            id="accordion-1"
            className={`transition-all w-full duration-200 ${
              !LookScreen && (!openIndex == 1 ? "" : "hidden")
            }`}
          >
            <div className="py-1 w-full rounded-md mt-1 ">
              {/* <NavLink
                onClick={() => setIsAddMem(true)}
                className="bg-transparent mt-2 mb-2 "
              >
                <img src="/addmember.png" width={150} alt="" srcset="" />
              </NavLink> */}
              <ul className="w-full h-[363px] scroll-box overflow-auto ">
                {employee
              .filter((rec) => rec.role !== "admin")
              .map((item, i) => (
                  <li className="mt-3 ">
                    <div className="flex items-center space-x-4 rtl:space-x-reverse">
                      <div
                        className={`w-[50px] h-[50px]  rounded-full ${color[i]} `}
                      >
                        <img
                          className=" w-full  rounded-full h-full"
                          src={item.pic?item.pic:"/noprofile.png"}
                          alt={item.img}
                        />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-[13px] font-medium  ">
                          {item.name}
                        </p>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
