import React, { useContext } from "react";
import Attachment from "./Attachment";
import Member from "./Member";
import EditGroup from "./EditGroup";
import { MyContext } from "../../context/GlobalContext";
import { MdOutlineClose } from "react-icons/md";
export default function GroupDetail() {
  const { isEditGroup, setEditGroup, LookScreen, GroupName, setSideDraw } =
    useContext(MyContext);
  return (
    <div className="bg-[#FFFFFF] h-[630px] w-[-webkit-fill-available] scroll-box  overflow-auto rounded-[24px] px-5 py-5">
      <div className="flex items-center w-full mt-2 justify-between">
        <div className="flex lg:hidden">
          <button
            className="bg-transparent "
            onClick={() => setSideDraw(false)}
          >
            <MdOutlineClose size={20} />{" "}
          </button>
        </div>
        {!LookScreen && (
          <button
            className="bg-transparent ms-auto "
            onClick={() => setEditGroup(!isEditGroup)}
          >
            {" "}
            <img src="/whiteedit.png" className="w-5" alt="" />{" "}
          </button>
        )}
      </div>
      <div className="flex flex-col items-center">
        <div className="w-[88px] h-[88px]">
          {GroupName.groupimg ? (
            <img
              src={GroupName.groupimg}
              className="w-full h-full rounded-full"
              alt=""
              srcset=""
            />
          ) : (
            <img
              src={"noprofile.png"}
              class="rounded-[50%] object-cover cursor-pointer w-[50px] h-[50px] lg:w-[50px] lg:h-[50px]"
              alt=""
            />
          )}
        </div>
        <h3 className="lg:text-base font-semibold leading-[19px] mt-3">
          {GroupName.group_name}
        </h3>
      </div>
      <Attachment />
      <Member />
      {/* Modal */}
      <EditGroup />
    </div>
  );
}
