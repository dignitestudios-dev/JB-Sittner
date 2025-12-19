import React, { useContext, useEffect, useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import EditEmp from "./editEmp";
import DeleteEmpProfile from "../Profile/DeleteProfile";
import {
  collection,
  db,
  getDocs,
  onSnapshot,
  query,
  where,
} from "../../firbase/FirebaseInit";
import { MyContext } from "../../context/GlobalContext";
import Loader from "../../global/Loader";

export default function EmployeeList() {
  const navgiate = useNavigate("");
  const [employee, setEmployee] = useState([]);
  const { setLoader, loader,setDeleteEmpId,setDeleteDocId } = useContext(MyContext);
  const getEmployee = () => {
    const employeesRef = collection(db, "employee");
    const employeeQuery = query(employeesRef);

    setLoader(true); // Set loader to true before fetching data

    const unsubscribe = onSnapshot(employeeQuery, (querySnapshot) => {
      const employeeData = querySnapshot.docs.map((doc) => ({
        docId: doc.id,
        ...doc.data(),
      }));
      setEmployee(employeeData);
      setLoader(false); 
    }, (error) => {
      console.error("Error fetching employees: ", error);
      setLoader(false); 
    });

    return unsubscribe;
  };

  useEffect(() => {
    const unsubscribe = getEmployee();
    return () => unsubscribe();
  }, []);

  

  return (
    <div className="bg-[#FFFFFF] border rounded-[10px] h-[70vh] border-[#E4E4E4] mt-6 py-3 px-3 lg:py-5 lg:px-5">
      <div className="relative scroll-box overflow-x-auto h-full ">
        {
          loader?(<Loader/>):(
        <table className="w-full text-sm text-left rtl:text-right text-gray-500 dark:text-gray-400">
          <thead className="text-xs text-[#787F8C] uppercase bg-[#F3F5F7]">
            <tr>
              <th scope="col" className="px-6 py-3 rounded-s-lg">
                Employee
              </th>
              <th scope="col" className="px-6 py-3">
                Email
              </th>
              <th scope="col" className="px-6 py-3 ">
                Contact
              </th>
              {/* <th scope="col" className="px-6 py-3 ">
                Address
              </th> */}
              <th scope="col" className="px-6 py-3 ">
                Action
              </th>
            </tr>
          </thead>
          <tbody>
            {employee
              .filter((rec) => rec.role !== "admin")
              .map((item, i) => (
                <tr key={i} className="bg-white  border-b-2 border-[#F4F4F4]  ">
                  <th
                    scope="row"
                    className="px-4 py-4  text-gray-900 whitespace-nowrap text-base font-normal"
                  >
                    <div
                      onClick={() =>
                        navgiate("/profile", { state: { id: item.id } })
                      }
                      className="flex cursor-pointer items-center gap-2"
                    >
                      <div className="bg-[#94D0E4] w-[32px] h-[32px] rounded-full">
                        <img
                          src={item?.pic ? item.pic : "/noprofile.png"}
                          alt=""
                          className="object-cover w-full h-full rounded-full"
                        />
                      </div>
                      <div>
                        <p className="text-[13px] font-normal">{item.name}</p>
                      </div>
                    </div>
                  </th>
                  <td className="px-6 text-[#181818] text-[13px] font-normal">
                    {item.email}
                  </td>
                  <td className="px-6 text-[13px] font-normal text-[#181818]">
                    {item.contact}
                  </td>
                  {/* <td className="px-6 text-[13px] w-[200px] lg:w-auto font-normal text-[#181818]">
                    <p className="w-[200px] overflow-auto text-nowrap lg:w-auto">
                      {item.address}
                    </p>
                  </td> */}
                  <td className="px-6 py-6" onClick={()=>{
                    setDeleteDocId(item.docId)
                    setDeleteEmpId(item.id)
                  }
                    } >
              
                    <EditEmp  />
                  </td>
                </tr>
              ))}
          </tbody>
        </table>
         )
        }
      </div>
      <DeleteEmpProfile />
    </div>
  );
}
